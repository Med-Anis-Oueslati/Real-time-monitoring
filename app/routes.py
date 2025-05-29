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

from sqlalchemy.orm import sessionmaker, scoped_session

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('landing.html')

@main.route('/signup', methods=['GET', 'POST'])
def signup():
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
    logout_form = LogoutForm()
    return render_template('dashboard.html', user=current_user, logout_form=logout_form)

@main.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.home'))

### Streamlit Integration

def is_streamlit_running():
    try:
        r = requests.get("http://localhost:8501")
        return r.status_code == 200
    except requests.ConnectionError:
        return False

@main.route('/start-streamlit', methods=['POST'])
@login_required
@csrf.exempt
def start_streamlit():
    if is_streamlit_running():
        return jsonify({"status": "already_running"})

    command = ["streamlit", "run", "/home/anis/PFE/agents/conversational_chatbot.py"]
    try:
        subprocess.Popen(command)
        time.sleep(2)
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
    """
    Executes an SSH command on a remote host.
    Returns (success: bool, message: str)
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    CONNECT_TIMEOUT = 10 
    COMMAND_EXEC_TIMEOUT = 30 

    try:
        ssh.connect(ip, username=username, password=password, timeout=CONNECT_TIMEOUT)

        full_command = ""
        if sudo_pass:
            full_command = f"echo {sudo_pass} | sudo -S {command} > /dev/null 2>&1 &"
        else:
            full_command = f"{command} > /dev/null 2>&1 &"

        stdin, stdout, stderr = ssh.exec_command(full_command, timeout=COMMAND_EXEC_TIMEOUT)

        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        ssh.close()

        if exit_status == 0 or exit_status == -1:
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
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip = vm.ip_address
    username = vm.ssh_username
    password = vm.ssh_password

    deploy_commands = []
    response_message = "Monitoring started."

    deploy_commands.append("/opt/zeek/bin/zeekctl deploy")
    deploy_commands.append("fluentd -c /etc/fluentd.conf -v")

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
            socketio.emit('vm_status_update', {vm.short_name: vm.status}, namespace='/')
            return jsonify({"status": "started", "message": response_message})
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
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip = vm.ip_address
    username = vm.ssh_username
    password = vm.ssh_password

    stop_commands = []
    stop_commands.append("/opt/zeek/bin/zeekctl stop")
    stop_commands.append("pkill -f fluentd")

    overall_success = True
    all_messages = []

    for cmd in stop_commands:
        success, msg = _execute_ssh_command(ip, username, password, cmd, password)
        if not success:
            overall_success = False
            all_messages.append(f"Command '{cmd}' failed: {msg}")

    if overall_success:
        vm.status = 'online'
        try:
            db.session.commit()
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
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip = vm.ip_address
    username = vm.ssh_username
    password = vm.ssh_password

    try:
        success, output = _execute_ssh_command(ip, username, password, "/sbin/shutdown now", password)
        if success:
            vm.status = 'offline'
            db.session.commit()
            socketio.emit('vm_status_update', {vm.short_name: vm.status}, namespace='/')
            return jsonify({"status": "shutdown"})
        else:
            db.session.rollback()
            return jsonify({"status": "failed", "message": f"Shutdown failed: {output}"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

def is_online(ip):
    """Checks if a VM is online via ping."""
    ping_executable_path = '/usr/bin/ping' # Ensure this path is correct for your system

    command = [ping_executable_path, '-c', '1', '-W', '1', ip]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
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
    form = AddVMForm()
    if form.validate_on_submit():
        existing_short_name_vm = VM.query.filter_by(user_id=current_user.id, short_name=form.short_name.data).first()
        if existing_short_name_vm:
            return jsonify({"status": "error", "message": "You already have a VM with this short name."}), 400

        existing_name_vm = VM.query.filter_by(user_id=current_user.id, name=form.name.data).first()
        if existing_name_vm:
            return jsonify({"status": "error", "message": "You already have a VM with this name."}), 400

        new_vm = VM(
            name=form.name.data,
            short_name=form.short_name.data,
            ip_address=form.ip_address.data,
            ssh_username=form.ssh_username.data,
            ssh_password=form.ssh_password.data if form.ssh_password.data else None,
            description=form.description.data,
            user_id=current_user.id,
            status='offline'
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
    form = EditVMForm()
    if form.validate_on_submit():
        vm_short_name = form.vm_short_name.data

        vm = VM.query.filter_by(short_name=vm_short_name, user_id=current_user.id).first()
        if not vm:
            return jsonify({"status": "error", "message": "Virtual Machine not found or you do not own it."}), 404
        
        if form.name.data != vm.name:
            existing_name_vm = VM.query.filter(
                VM.user_id == current_user.id,
                VM.name == form.name.data,
                VM.id != vm.id
            ).first()
            if existing_name_vm:
                return jsonify({"status": "error", "message": "You already have another VM with this name."}), 400
        
        vm.name = form.name.data
        vm.ip_address = form.ip_address.data
        vm.ssh_username = form.ssh_username.data
        if form.ssh_password.data:
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

thread = None
thread_lock = Lock()

def background_vm_status_monitor(app):
    """
    Background thread that periodically checks VM statuses and emits updates.
    """
    while True:
        current_statuses = {}
        ping_threads = []
        
        with app.app_context():
            all_vm_short_names = [vm.short_name for vm in VM.query.all()]

            for vm_short_name in all_vm_short_names:
                ping_threads.append(Thread(target=_check_single_vm_status, args=(app, vm_short_name, current_statuses)))
            
            for t in ping_threads:
                t.start()
            for t in ping_threads:
                t.join()

            socketio.emit('vm_status_update', current_statuses, namespace='/')

        socketio.sleep(5)

def _check_single_vm_status(app, vm_short_name, status_dict):
    """
    Helper to check individual VM status and update a shared dictionary.
    Manages its own SQLAlchemy session for isolation.
    """
    with app.app_context():
        Session = sessionmaker(bind=db.engine)
        session = Session()

        try:
            vm_obj = session.query(VM).filter_by(short_name=vm_short_name).first()
            if not vm_obj:
                return

            current_db_status = vm_obj.status
            final_status = current_db_status

            # --- MODIFIED LOGIC ---
            # If the VM is in 'monitoring' state, *do not change it unless a specific action causes it*.
            # The background monitor will simply report 'monitoring' back.
            if current_db_status == 'monitoring':
                final_status = 'monitoring' # Always maintain 'monitoring' if it's already set
            elif current_db_status == 'offline':
                # If DB says 'offline', ping to see if it came back online.
                is_vm_online = is_online(vm_obj.ip_address)
                if is_vm_online:
                    final_status = "online" # It came back online!
                else:
                    final_status = "offline" # Still offline.
            else: # This covers 'online'
                # If DB says 'online', ping to confirm it's still online.
                is_vm_online = is_online(vm_obj.ip_address)
                if is_vm_online:
                    final_status = "online"
                else:
                    final_status = "offline"
            # --- END MODIFIED LOGIC ---

            if vm_obj.status != final_status:
                vm_obj.status = final_status
                try:
                    session.commit()
                except Exception as e:
                    session.rollback()
            
            with thread_lock:
                status_dict[vm_obj.short_name] = final_status

        finally:
            session.close()
### SocketIO Event Handlers

@socketio.on('connect', namespace='/')
def test_connect(*args):
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(target=background_vm_status_monitor, app=current_app._get_current_object())
        
    with current_app.app_context():
        if current_user.is_authenticated:
            Session = sessionmaker(bind=db.engine)
            session = Session()
            try:
                all_vms = session.query(VM).filter_by(user_id=current_user.id).all()
                initial_statuses = {}
                for vm_obj in all_vms:
                    initial_statuses[vm_obj.short_name] = vm_obj.status
                emit('vm_status_update', initial_statuses)
            finally:
                session.close()
        else:
            emit('vm_status_update', {})

@socketio.on('disconnect', namespace='/')
def test_disconnect():
    pass