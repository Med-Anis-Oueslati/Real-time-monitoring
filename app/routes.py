# app/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms import SignUpForm, LoginForm, LogoutForm, EditVMForm, AddVMForm
from .models import User, VM
from . import db, csrf, socketio
import subprocess
import time
import requests
import socket
import paramiko
from threading import Thread, Lock
from flask_login import login_user, logout_user, login_required, current_user
from flask_socketio import emit
from sqlalchemy.orm import sessionmaker
import os 

# Import MitigationUtility
from .mitigation_utils import MitigationUtility, MitigationAction

# NEW: Import AnomalyDetectionAgent and pika for RabbitMQ consumer
from agents.anomaly_detection_agent import AnomalyDetectionAgent, IncidentDescription
import pika
import json
import logging

logger = logging.getLogger(__name__)

# Create a Blueprint for main routes
main = Blueprint('main', __name__)

# Global variables for anomaly detection background threads
anomaly_detection_thread = None
anomaly_consumer_thread = None
anomaly_thread_lock = Lock()


@main.route('/')
def home():
    """Renders the landing page."""
    return render_template('landing.html')

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user signup."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = SignUpForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.lower()
        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash('Username or email already taken.', 'error')
        else:
            hashed_pw = generate_password_hash(form.password.data)
            new_user = User(username=username, email=email, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('main.login'))
    return render_template('signup.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.html', form=form)

@main.route('/dashboard')
@login_required
def dashboard():
    """Renders the user dashboard."""
    logout_form = LogoutForm()
    return render_template('dashboard.html', user=current_user, logout_form=logout_form)

@main.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.home'))


### Streamlit Integration

def is_streamlit_running():
    """Checks if the Streamlit application is running."""
    try:
        r = requests.get("http://localhost:8501")
        return r.status_code == 200
    except requests.ConnectionError:
        return False

@main.route('/start-streamlit', methods=['POST'])
@login_required
@csrf.exempt
def start_streamlit():
    """Starts the Streamlit chatbot application."""
    if is_streamlit_running():
        return jsonify({"status": "already_running"})

    command = ["streamlit", "run", "/home/anis/PFE/agents/conversational_chatbot.py"]
    try:
        subprocess.Popen(command)
        time.sleep(2)  # Give Streamlit time to start
        if is_streamlit_running():
            return jsonify({"status": "started"})
        else:
            return jsonify({"status": "failed", "message": "Streamlit process started but not accessible."})
    except FileNotFoundError:
        return jsonify({"status": "failed", "message": "Streamlit command not found. Is Streamlit installed and in PATH?"}), 500
    except Exception as e:
        return jsonify({"status": "failed", "message": f"Error starting Streamlit: {str(e)}"}), 500


### VM Monitoring & Management

def _execute_ssh_command(ip, username, password, command, sudo_pass=None):
    """Executes an SSH command on a remote host."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    CONNECT_TIMEOUT = 10
    COMMAND_EXEC_TIMEOUT = 30

    try:
        ssh.connect(ip, username=username, password=password, timeout=CONNECT_TIMEOUT)

        # Build the command string, including sudo if a password is provided
        full_command = f"echo {sudo_pass} | sudo -S {command} > /dev/null 2>&1 &" if sudo_pass else f"{command} > /dev/null 2>&1 &"

        stdin, stdout, stderr = ssh.exec_command(full_command, timeout=COMMAND_EXEC_TIMEOUT)

        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        ssh.close()

        if exit_status == 0 or exit_status == -1: # -1 often indicates background process
            return True, "Command initiated in background."
        else:
            err_msg = f"Command failed to initiate (exit status {exit_status}). Output: '{output}', Error: '{error}'"
            return False, err_msg

    except paramiko.AuthenticationException:
        return False, "Authentication failed. Check username/password."
    except paramiko.SSHException as e:
        return False, f"SSH connection or command execution failed: {e}"
    except socket.timeout:
        return False, "Timed out during SSH connection or command initiation."
    except Exception as e:
        return False, f"An unexpected error occurred: {e}"

@main.route("/vm-monitoring")
@login_required
def vm_monitoring():
    """Renders the VM monitoring page."""
    vms = VM.query.filter_by(user_id=current_user.id).all()
    add_form = AddVMForm()
    edit_form = EditVMForm()
    return render_template(
        "vm_monitoring.html",
        vms=vms,
        add_form=add_form,
        edit_form=edit_form
    )

@main.route("/start-monitoring", methods=["POST"])
@login_required
@csrf.exempt
def start_monitoring():
    """Starts monitoring services (Zeek and Fluentd) on a VM."""
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip, username, password = vm.ip_address, vm.ssh_username, vm.ssh_password
    
    # Commands to deploy Zeek and start Fluentd
    deploy_commands = [
        "/opt/zeek/bin/zeekctl deploy",
        "fluentd -c /etc/fluentd.conf -v"
    ]

    overall_success = True
    all_messages = []
    for cmd in deploy_commands:
        success, message = _execute_ssh_command(ip, username, password, cmd, sudo_pass=password)
        if not success:
            overall_success = False
            all_messages.append(f"Command '{cmd}' failed: {message}")

    if overall_success:
        vm.status = 'monitoring'
        try:
            db.session.commit()
            # Emit status update via SocketIO
            socketio.emit('vm_status_update', {vm.short_name: vm.status}, namespace='/')
            return jsonify({"status": "started", "message": "Monitoring started."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "failed", "message": f"Failed to update VM status in DB: {e}"})
    else:
        db.session.rollback()
        return jsonify({"status": "failed", "message": f"Monitoring failed: {'; '.join(all_messages)}"})

@main.route("/stop-monitoring", methods=["POST"])
@login_required
@csrf.exempt
def stop_monitoring():
    """Stops monitoring services (Zeek and Fluentd) on a VM."""
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip, username, password = vm.ip_address, vm.ssh_username, vm.ssh_password

    # Commands to stop Zeek and kill Fluentd
    stop_commands = [
        "/opt/zeek/bin/zeekctl stop",
        "pkill -f fluentd"
    ]

    overall_success = True
    all_messages = []

    for cmd in stop_commands:
        success, msg = _execute_ssh_command(ip, username, password, cmd, password)
        if not success:
            overall_success = False
            all_messages.append(f"Command '{cmd}' failed: {msg}")

    if overall_success:
        vm.status = 'online' # Set status back to online after stopping monitoring
        try:
            db.session.commit()
            # Emit status update via SocketIO
            socketio.emit('vm_status_update', {vm.short_name: vm.status}, namespace='/')
            return jsonify({"status": "stopped"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "failed", "message": f"Failed to update VM status in DB: {e}"})
    else:
        db.session.rollback()
        return jsonify({"status": "failed", "message": f"Stop monitoring failed: {'; '.join(all_messages)}"})

@main.route("/shutdown-vm", methods=["POST"])
@login_required
@csrf.exempt
def shutdown_vm():
    """Shuts down a VM gracefully."""
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip, username, password = vm.ip_address, vm.ssh_username, vm.ssh_password

    try:
        success, output = _execute_ssh_command(ip, username, password, "/sbin/shutdown now", password)
        if success:
            vm.status = 'offline'
            db.session.commit()
            # Emit status update via SocketIO
            socketio.emit('vm_status_update', {vm.short_name: vm.status}, namespace='/')
            return jsonify({"status": "shutdown"})
        else:
            db.session.rollback()
            return jsonify({"status": "failed", "message": f"Shutdown failed: {output}"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

def is_online(ip):
    """Checks if a VM is online using a ping command."""
    ping_executable_path = '/usr/bin/ping' # Path to ping executable

    command = [ping_executable_path, '-c', '1', '-W', '1', ip] # Ping once, wait 1 second
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False, # Don't raise an exception for non-zero exit codes
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except Exception as e:
        return False

@main.route("/add-vm", methods=["POST"])
@login_required
@csrf.exempt
def add_vm():
    """Adds a new VM to the user's list."""
    form = AddVMForm()
    if form.validate_on_submit():
        # Check for existing VM with same short name or name for the current user
        if VM.query.filter_by(user_id=current_user.id, short_name=form.short_name.data).first():
            return jsonify({"status": "error", "message": "You already have a VM with this short name."}), 400
        if VM.query.filter_by(user_id=current_user.id, name=form.name.data).first():
            return jsonify({"status": "error", "message": "You already have a VM with this name."}), 400

        new_vm = VM(
            name=form.name.data,
            short_name=form.short_name.data,
            ip_address=form.ip_address.data,
            ssh_username=form.ssh_username.data,
            ssh_password=form.ssh_password.data if form.ssh_password.data else None,
            description=form.description.data,
            user_id=current_user.id,
            status='offline' # Default status
        )
        try:
            db.session.add(new_vm)
            db.session.commit()
            flash(f"VM '{new_vm.name}' added successfully!", "success")
            return jsonify({"status": "success", "message": "VM added."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "error", "message": f"Failed to add VM: {str(e)}"}), 500
    else:
        errors = {field.name: field.errors for field in form if field.errors}
        return jsonify({"status": "error", "message": "Validation failed.", "errors": errors}), 400

@main.route("/edit-vm-details", methods=["POST"])
@login_required
@csrf.exempt
def edit_vm_details():
    """Edits details of an existing VM."""
    form = EditVMForm()
    if form.validate_on_submit():
        vm_short_name = form.vm_short_name.data

        vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
        if not vm:
            return jsonify({"status": "error", "message": "Virtual Machine not found or you do not own it."}), 404
        
        # Check if the new name conflicts with other VMs of the same user
        if form.name.data != vm.name:
            existing_name_vm = VM.query.filter(
                VM.user_id == current_user.id,
                VM.name == form.name.data,
                VM.id != vm.id # Exclude the current VM
            ).first()
            if existing_name_vm:
                return jsonify({"status": "error", "message": "You already have another VM with this name."}), 400
        
        # Update VM details
        vm.name = form.name.data
        vm.ip_address = form.ip_address.data
        vm.ssh_username = form.ssh_username.data
        if form.ssh_password.data: # Only update password if provided
            vm.ssh_password = form.ssh_password.data
        vm.description = form.description.data

        try:
            db.session.commit()
            flash(f"VM '{vm.name}' updated successfully!", "success")
            return jsonify({"status": "success", "message": "VM updated."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "error", "message": f"Failed to update VM: {str(e)}"}), 500
    else:
        errors = {field.name: field.errors for field in form if field.errors}
        return jsonify({"status": "error", "message": "Validation failed.", "errors": errors}), 400

@main.route("/delete-vm", methods=["POST"])
@login_required
@csrf.exempt
def delete_vm():
    """Deletes a VM from the user's list."""
    data = request.get_json()
    vm_short_name = data.get("vm_short_name")

    vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found or you do not own it."}), 404

    try:
        db.session.delete(vm)
        db.session.commit()
        flash(f"VM '{vm.name}' deleted successfully!", "success")
        return jsonify({"status": "success", "message": "VM deleted."})
    except Exception as e:
            db.session.rollback()
            return jsonify({"status": "error", "message": f"Failed to delete VM: {str(e)}"}), 500
    

### Background Thread for VM Status Monitoring

# Global variables for the background thread and its lock
thread = None
thread_lock = Lock()

def background_vm_status_monitor(app):
    """Periodically checks VM statuses and emits updates via SocketIO."""
    while True:
        current_statuses = {}
        ping_threads = []
        
        with app.app_context():
            # Get all VM short names to check
            all_vm_short_names = [vm.short_name for vm in VM.query.all()]

            # Create a thread for each VM status check
            for vm_short_name in all_vm_short_names:
                ping_threads.append(Thread(target=_check_single_vm_status, args=(app, vm_short_name, current_statuses)))
            
            # Start and join all threads
            for t in ping_threads:
                t.start()
            for t in ping_threads:
                t.join()

            # Emit all gathered statuses to connected clients
            socketio.emit('vm_status_update', current_statuses, namespace='/')

        socketio.sleep(5) # Wait for 5 seconds before next check

def _check_single_vm_status(app, vm_short_name, status_dict):
    """Helper to check an individual VM's status and update a shared dictionary."""
    with app.app_context():
        # Use a new session for each thread to avoid conflicts
        Session = sessionmaker(bind=db.engine)
        session = Session()

        try:
            vm_obj = session.query(VM).filter_by(short_name=vm_short_name).first()
            if not vm_obj:
                return

            current_db_status = vm_obj.status
            final_status = current_db_status

            # If VM is "monitoring", keep it as "monitoring"
            if current_db_status == 'monitoring':
                final_status = 'monitoring'
            else: # For 'offline' or 'online'
                is_vm_online = is_online(vm_obj.ip_address)
                if is_vm_online:
                    final_status = "online"
                else:
                    final_status = "offline"
            
            # Update VM status in the database if it has changed
            if vm_obj.status != final_status:
                vm_obj.status = final_status
                try:
                    session.commit()
                except Exception as e:
                    session.rollback()
            
            # Update the shared status dictionary
            with thread_lock:
                status_dict[vm_obj.short_name] = final_status

        finally:
            session.close()


### SocketIO Event Handlers

@socketio.on('connect', namespace='/')
def test_connect(*args):
    """Handles new SocketIO connections."""
    global thread, anomaly_consumer_thread # Include anomaly_consumer_thread
    with thread_lock: # Use the same lock for all background threads for simplicity
        # Start VM status monitoring thread if it's not already running
        if thread is None:
            thread = socketio.start_background_task(target=background_vm_status_monitor, app=current_app._get_current_object())
        
        # NEW: Start RabbitMQ anomaly consumer thread if not already running
        if anomaly_consumer_thread is None:
            anomaly_consumer_thread = socketio.start_background_task(target=rabbitmq_anomaly_consumer, app=current_app._get_current_object())
            logger.info("RabbitMQ anomaly consumer thread started.")

    with current_app.app_context():
        # Emit initial VM statuses to the newly connected client
        if current_user.is_authenticated:
            Session = sessionmaker(bind=db.engine)
            session = Session()
            try:
                all_vms = session.query(VM).filter_by(user_id=current_user.id).all()
                initial_statuses = {vm_obj.short_name: vm_obj.status for vm_obj in all_vms}
                emit('vm_status_update', initial_statuses)
            finally:
                session.close()
        else:
            emit('vm_status_update', {}) # No VMs for unauthenticated users

@socketio.on('disconnect', namespace='/')
def test_disconnect():
    """Handles SocketIO disconnections (placeholder)."""
    pass

# Route for Mitigation Agent Interaction Page
@main.route("/mitigation-agent-interaction")
@login_required
def mitigation_agent_interaction():
    """Renders the page for interacting with the mitigation agent."""
    vms = VM.query.filter_by(user_id=current_user.id).all()
    # Pass VMs to the template so the user can select one to interact with
    return render_template("mitigation_agent_interaction.html", vms=vms)

# SocketIO event for generating mitigation commands
@socketio.on('generate_mitigation', namespace='/')
@login_required
def handle_generate_mitigation(data):
    """
    Handles requests to generate mitigation commands based on an incident description.
    """
    incident_description = data.get('incident_description')
    if not incident_description:
        emit('mitigation_response', {'status': 'error', 'message': 'Incident description is required.'})
        return

    # Access mitigation_utility from the current_app object
    mitigation_utility_instance = current_app.mitigation_utility 
    if not mitigation_utility_instance:
        emit('mitigation_response', {'status': 'error', 'message': 'Mitigation agent not initialized. Check server logs.'})
        return

    try:
        action = mitigation_utility_instance.generate_mitigation_action(incident_description)
        emit('mitigation_response', {
            'status': 'success',
            'description': action.description,
            'commands': action.commands
        })
    except Exception as e:
        emit('mitigation_response', {'status': 'error', 'message': f'Error generating mitigation: {str(e)}'})

# SocketIO event for executing mitigation commands
@socketio.on('execute_commands', namespace='/')
@login_required
def handle_execute_commands(data):
    """
    Handles requests to execute mitigation commands on a selected VM.
    """
    vm_short_name = data.get('vm_short_name')
    commands = data.get('commands')

    if not vm_short_name or not commands:
        emit('execution_response', {'status': 'error', 'message': 'VM short name and commands are required.'})
        return

    # Access mitigation_utility from the current_app object
    mitigation_utility_instance = current_app.mitigation_utility
    if not mitigation_utility_instance:
        emit('execution_response', {'status': 'error', 'message': 'Mitigation agent not initialized. Check server logs.'})
        return

    with current_app.app_context():
        vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
        if not vm:
            emit('execution_response', {'status': 'error', 'message': 'Virtual Machine not found or you do not own it.'})
            return

        if not vm.ssh_password:
            emit('execution_response', {'status': 'error', 'message': 'SSH password not set for this VM. Cannot execute commands.'})
            return

        try:
            results = mitigation_utility_instance.execute_mitigation_commands(
                vm.ip_address, vm.ssh_username, vm.ssh_password, commands
            )
            emit('execution_response', {
                'status': 'success',
                'results': results, # List of (success, message) tuples for each command
                'vm_short_name': vm_short_name
            })
        except Exception as e:
            emit('execution_response', {'status': 'error', 'message': f'Error executing commands: {str(e)}'})


# NEW: Route for Anomaly Detection Page
@main.route("/anomaly-detection")
@login_required
def anomaly_detection():
    """Renders the page for anomaly detection."""
    # We might want to fetch initial anomalies from DB here, or just let SocketIO populate
    return render_template("anomaly_detection.html")

# NEW: SocketIO event to start anomaly sweep
@socketio.on('start_anomaly_sweep', namespace='/')
@login_required
def handle_start_anomaly_sweep():
    """
    Starts the anomaly detection agent as a background process.
    """
    global anomaly_detection_thread
    with anomaly_thread_lock:
        if anomaly_detection_thread and anomaly_detection_thread.is_alive():
            emit('anomaly_sweep_status', {'status': 'info', 'message': 'Anomaly detection sweep is already running.'})
            return

        # Start the anomaly detection agent as a separate process
        # Ensure the path to anomaly_detection_agent.py is correct
        command = ["python", "/home/anis/PFE/agents/anomaly_detection_agent.py"]
        try:
            # Using Popen to run it detached, so it doesn't block the Flask process
            # and doesn't get killed if the Flask process reloads.
            # stdout=subprocess.PIPE, stderr=subprocess.PIPE can be used for logging,
            # but for now, we'll let it run independently.
            subprocess.Popen(command, cwd="/home/anis/PFE/") # Run from project root
            emit('anomaly_sweep_status', {'status': 'success', 'message': 'Anomaly detection sweep started.'})
            logger.info("Anomaly detection agent process launched.")
        except FileNotFoundError:
            emit('anomaly_sweep_status', {'status': 'error', 'message': 'Python or anomaly_detection_agent.py not found.'})
            logger.error("Failed to launch anomaly detection agent: File not found.")
        except Exception as e:
            emit('anomaly_sweep_status', {'status': 'error', 'message': f'Error launching anomaly detection: {str(e)}'})
            logger.error(f"Error launching anomaly detection agent: {e}")

# NEW: RabbitMQ Consumer as a background task
def rabbitmq_anomaly_consumer(app):
    """
    Consumes anomaly messages from RabbitMQ and emits them via SocketIO.
    Runs in a separate thread.
    """
    connection = None
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.queue_declare(queue='anomaly_queue', durable=True)
        logger.info('RabbitMQ consumer started. Waiting for messages...')

        def callback(ch, method, properties, body):
            try:
                anomaly_data = json.loads(body)
                logger.info(f"Received anomaly message: {anomaly_data}")
                with app.app_context():
                    # Emit to all connected clients in the '/anomaly' namespace
                    # Or to the default namespace if no specific namespace is used
                    socketio.emit('new_anomaly', anomaly_data, namespace='/')
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON from RabbitMQ message: {e} - Body: {body}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Nack bad messages
            except Exception as e:
                logger.error(f"Error processing RabbitMQ message: {e}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Nack on other errors

        channel.basic_consume(queue='anomaly_queue', on_message_callback=callback, auto_ack=False)
        channel.start_consuming()
    except pika.exceptions.AMQPConnectionError as e:
        logger.error(f"RabbitMQ connection error in consumer: {e}")
    except Exception as e:
        logger.error(f"Unhandled error in RabbitMQ consumer: {e}")
    finally:
        if connection and not connection.is_closed:
            connection.close()
            logger.info("RabbitMQ consumer connection closed.")

# NEW: SocketIO event for approving mitigation
@socketio.on('approve_mitigation', namespace='/')
@login_required
def handle_approve_mitigation(data):
    """
    Handles user approval of a proposed mitigation action.
    Sends the commands to the MitigationUtility for execution.
    """
    incident_description = data.get('incident_description')
    commands = data.get('commands')
    src_ip = data.get('src_ip')
    dst_ip = data.get('dst_ip')
    anomaly_type = data.get('anomaly_type')

    if not commands:
        emit('mitigation_approval_status', {'status': 'error', 'message': 'No commands provided for mitigation.'})
        return

    mitigation_utility_instance = current_app.mitigation_utility
    if not mitigation_utility_instance:
        emit('mitigation_approval_status', {'status': 'error', 'message': 'Mitigation agent not initialized. Cannot execute.'})
        return

    # For simplicity, we'll assume a target VM for now.
    # In a real scenario, you'd need to determine the target VM based on src_ip/dst_ip or user input.
    # For now, let's pick the first available VM or a default one if needed.
    # This part needs careful consideration based on your VM management.
    # For demonstration, let's assume we execute on 'lubuntu' if it's the source or destination.
    # Or, if no specific VM is identified, we might need a general "firewall" VM.
    
    # A more robust solution would involve:
    # 1. Storing VM details with the anomaly if it's VM-specific.
    # 2. Allowing the user to select a target VM for the mitigation.
    # For now, let's try to map to a VM based on IP if possible, or use a default.

    target_vm = None
    with current_app.app_context():
        # Try to find a VM matching source or destination IP
        if src_ip:
            target_vm = VM.query.filter_by(ip_address=src_ip, user_id=current_user.id).first()
        if not target_vm and dst_ip:
            target_vm = VM.query.filter_by(ip_address=dst_ip, user_id=current_user.id).first()
        
        # Fallback to a predefined VM if no specific VM is found by IP
        # You might want to make this configurable or require user selection
        if not target_vm:
            # Example: Try to find a VM named 'lubuntu' or 'kali'
            target_vm = VM.query.filter_by(short_name='lubuntu', user_id=current_user.id).first()
            if not target_vm:
                target_vm = VM.query.filter_by(short_name='kali', user_id=current_user.id).first()

    if not target_vm:
        emit('mitigation_approval_status', {'status': 'error', 'message': 'Could not determine a target VM for mitigation. Please execute manually.'})
        return
    
    if not target_vm.ssh_password:
        emit('mitigation_approval_status', {'status': 'error', 'message': f'SSH password not set for VM {target_vm.name}. Cannot execute commands.'})
        return

    try:
        # Execute commands using the MitigationUtility
        results = mitigation_utility_instance.execute_mitigation_commands(
            target_vm.ip_address, target_vm.ssh_username, target_vm.ssh_password, commands
        )
        # Summarize results for the user
        success_count = sum(1 for s, m in results if s)
        fail_count = len(results) - success_count
        overall_status = 'success' if fail_count == 0 else 'partial_success'
        message = f"Mitigation for '{anomaly_type}' on {target_vm.name} completed. {success_count} commands succeeded, {fail_count} failed."
        
        emit('mitigation_approval_status', {
            'status': overall_status,
            'message': message,
            'details': results # Send full results for detailed display
        })
        logger.info(f"Mitigation for anomaly '{anomaly_type}' approved and executed on {target_vm.name}.")

    except Exception as e:
        emit('mitigation_approval_status', {'status': 'error', 'message': f'Error executing approved mitigation: {str(e)}'})
        logger.error(f"Error executing approved mitigation for anomaly: {e}")

# NEW: SocketIO event for denying mitigation
@socketio.on('deny_mitigation', namespace='/')
@login_required
def handle_deny_mitigation(data):
    """
    Handles user denial of a proposed mitigation action.
    """
    anomaly_type = data.get('anomaly_type', 'Unknown Anomaly')
    emit('mitigation_approval_status', {'status': 'info', 'message': f'Mitigation for "{anomaly_type}" denied by user.'})
    logger.info(f"Mitigation for anomaly '{anomaly_type}' denied by user.")

