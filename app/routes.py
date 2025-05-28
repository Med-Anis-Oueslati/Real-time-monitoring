# app/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms import SignUpForm, LoginForm, LogoutForm, EditVMForm
from .models import User, VM # Import the new VM model
from . import db, csrf
import subprocess
import time
import requests
import paramiko
from threading import Thread
from flask_login import login_user, logout_user, login_required, current_user

main = Blueprint('main', __name__)

# --- Authentication Routes (no changes here from last update) ---

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

# --- Streamlit Integration (no changes) ---

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

# --- VM Monitoring & Management ---

# REMOVE hardcoded IPs and SSH_CREDENTIALS here!
# They will be fetched from the database.

def _execute_ssh_command(ip, username, password, command, sudo_pass=None):
    """
    Helper function to execute SSH commands.
    Returns (success: bool, message: str)
    """
    print(f"[SSH] Connecting to {ip} as {username} to execute: {command}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip, username=username, password=password, timeout=5)

        if sudo_pass:
            full_command = f"echo {sudo_pass} | sudo -S {command}"
            print(f"[SSH] Full command with sudo: {full_command}")
        else:
            full_command = command

        # Shorter timeout for commands that cause immediate disconnection
        command_timeout = 5
        if "shutdown" not in command and "reboot" not in command:
            # Give general commands more time, like Zeek deploy or pkill if they take a moment
            command_timeout = 15

        stdin, stdout, stderr = ssh.exec_command(full_command, timeout=command_timeout)

        # Read output and error streams
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        # Get exit status. If connection closes prematurely, this might be -1.
        exit_status = stdout.channel.recv_exit_status()

        ssh.close()

        # --- Simplified Success Logic ---
        # If exit_status is 0, it's definitely a success.
        # If exit_status is -1, it means the channel closed, often due to command success (e.g., shutdown, pkill).
        # We'll consider it a success if there's no actual error message from the command itself.
        if exit_status == 0:
            if error:
                print(f"[SSH WARNING on {ip}] Command: '{full_command}' succeeded (exit 0) but had stderr: '{error}'")
            print(f"[SSH INFO on {ip}] Command: '{full_command}' succeeded (exit 0). Output: '{output}'")
            return True, output
        elif exit_status == -1:
            # This often happens when the remote process exits quickly and closes the channel,
            # or for commands like 'pkill'/'shutdown' that can terminate the session.
            # Assume success if there's no actual error output from the command.
            if not error and not output: # If both are empty, it's usually a quiet success
                print(f"[SSH INFO on {ip}] Command: '{full_command}' initiated, channel closed (exit -1), no output/error. Assuming success.")
                return True, "Command initiated successfully (connection closed)."
            elif "No such process" in error or "No such process" in output:
                # pkill might return this if the process wasn't running, which is still a "success" for stopping it.
                print(f"[SSH INFO on {ip}] Command: '{full_command}' (exit -1). Process not found. Assuming stop success.")
                return True, "Process was not running."
            else:
                # If there's an actual error message, even with -1 status, it's a failure.
                print(f"[SSH ERROR on {ip}] Command: '{full_command}' failed (exit -1). Output: '{output}', Error: '{error}'")
                return False, f"Command failed: {error}"
        else:
            # Any other non-zero exit status indicates a failure.
            full_error_message = f"Command exited with status {exit_status}. Output: '{output}'. Error: '{error}'"
            print(f"[SSH ERROR on {ip}] {full_command}: {full_error_message}")
            return False, full_error_message

    except paramiko.AuthenticationException:
        print(f"[SSH AUTH ERROR] Authentication failed for {username}@{ip}")
        return False, "Authentication failed. Check username/password."
    except paramiko.SSHException as e:
        print(f"[SSH CONNECTION ERROR] Could not establish SSH connection to {ip}: {e}")
        # For shutdown/reboot or commands that cause connection reset,
        # it might mean the command was initiated.
        expected_ssh_exceptions = ["timed out", "broken pipe", "connection reset", "connection refused", "channel closed", "Error reading SSH protocol banner"]
        if any(err_msg in str(e).lower() for err_msg in expected_ssh_exceptions):
            print(f"[SSH INFO on {ip}] Assuming command initiated despite SSH connection error: {e}")
            return True, f"Command initiated (SSH connection error: {e})."
        return False, f"SSH connection failed: {e}"
    except Exception as e:
        print(f"[GENERIC SSH ERROR] An unexpected error occurred: {e}")
        return False, f"An unexpected error occurred: {e}"

@main.route("/vm-monitoring")
@login_required
def vm_monitoring():
    vms = VM.query.all()
    # Pass an instance of the EditVMForm to the template for each VM
    # Or, pass one global form and handle it with JavaScript for modals/dynamic forms.
    # For simplicity, let's pass a new form instance for the modal.
    edit_form = EditVMForm()
    return render_template("vm_monitoring.html", vms=vms, edit_form=edit_form)

# NEW ROUTE: To handle IP updates
@main.route("/update-vm-ip", methods=["POST"])
@login_required
@csrf.exempt # Keep exempt for AJAX if not sending CSRF token via JS
def update_vm_ip():
    form = EditVMForm()
    if form.validate_on_submit():
        vm_short_name = request.form.get('vm_short_name') # Get hidden field from form
        new_ip = form.ip_address.data

        vm = VM.query.filter_by(short_name=vm_short_name).first()
        if not vm:
            return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

        try:
            vm.ip_address = new_ip
            db.session.commit()
            flash(f"IP address for {vm.name} updated successfully to {new_ip}.", "success")
            return jsonify({"status": "success", "message": "IP updated."})
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to update IP for {vm.name}: {str(e)}", "error")
            return jsonify({"status": "error", "message": f"Failed to update IP: {str(e)}"}), 500
    else:
        # If form validation fails, send back errors
        errors = {field.name: field.errors for field in form if field.errors}
        return jsonify({"status": "error", "message": "Validation failed.", "errors": errors}), 400


# app/routes.py (relevant part of start_monitoring)

@main.route("/start-monitoring", methods=["POST"])
@login_required
@csrf.exempt
def start_monitoring():
    data = request.get_json()
    vm_short_name = data.get("vm")

    print(f"📥 Received request to /start-monitoring for VM: {vm_short_name}") # <-- Your new print

    vm = VM.query.filter_by(short_name=vm_short_name).first()
    if not vm:
        print(f"❌ VM '{vm_short_name}' not found.")
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip = vm.ip_address
    username = vm.ssh_username
    password = vm.ssh_password

    # THIS IS THE CRITICAL SECTION:
    if vm.short_name == 'kali': # Your current code has this condition
        deploy_command = "/opt/zeek/bin/zeekctl deploy"
        print(f"🔧 Attempting Zeek deployment on {vm_short_name} ({ip}). Command: {deploy_command}") # <-- Your new print
        success, message = _execute_ssh_command(ip, username, password, deploy_command, sudo_pass=password)

        print(f"🔍 _execute_ssh_command returned: success={success}, message='{message}'") # <-- Your new print

        if success:
            vm.status = 'monitoring'
            db.session.commit()
            print(f"✅ {vm_short_name} Zeek monitoring started, DB updated.") # <-- Your new print
            return jsonify({"status": "started", "message": "Zeek monitoring started."})
        else:
            db.session.rollback()
            print(f"❌ {vm_short_name} Zeek deploy failed. Error: {message}") # <-- Your new print
            return jsonify({"status": "failed", "message": f"Zeek deploy failed: {message}"})
    else: # This 'else' block handles all VMs that are NOT 'kali' (like Lubuntu)
        vm.status = 'monitoring' # It only updates the DB status
        db.session.commit()
        print(f"✅ {vm_short_name} monitoring status updated (no Zeek deploy).") # <-- Your new print
        return jsonify({"status": "started", "message": "Monitoring status updated."})


@main.route("/stop-monitoring", methods=["POST"])
@login_required
@csrf.exempt
def stop_monitoring():
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip = vm.ip_address
    username = vm.ssh_username
    password = vm.ssh_password

    try:
        print(f"Stopping monitoring on {vm.name}...")
        # Attempt to kill both processes. Even if one fails, try the other.
        success_zeek, zeek_msg = _execute_ssh_command(ip, username, password, "pkill -f zeekctl", password)
        success_fluentd, fluentd_msg = _execute_ssh_command(ip, username, password, "pkill -f fluentd", password)

        if success_zeek and success_fluentd:
            vm.status = 'online' # Assume online after stopping monitoring
            db.session.commit()
            print(f"Monitoring stopped for {vm.name}")
            return jsonify({"status": "stopped"})
        else:
            # If at least one failed, report it.
            error_msg = []
            if not success_zeek: error_msg.append(f"Zeek stop failed: {zeek_msg}")
            if not success_fluentd: error_msg.append(f"Fluentd stop failed: {fluentd_msg}")
            return jsonify({"status": "failed", "message": "; ".join(error_msg)})
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Stop monitoring failed for {vm.name}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@main.route("/shutdown-vm", methods=["POST"])
@login_required
@csrf.exempt
def shutdown_vm():
    data = request.get_json()
    vm_short_name = data.get("vm")

    vm = VM.query.filter_by(short_name=vm_short_name).first()
    if not vm:
        return jsonify({"status": "error", "message": "Virtual Machine not found."}), 404

    ip = vm.ip_address
    username = vm.ssh_username
    password = vm.ssh_password # Sudo password

    try:
        print(f"Shutting down VM {vm.name}...")
        success, output = _execute_ssh_command(ip, username, password, "/sbin/shutdown now", password)
        if success:
            vm.status = 'offline' # Update status after shutdown attempt
            db.session.commit()
            return jsonify({"status": "shutdown"})
        else:
            db.session.rollback()
            return jsonify({"status": "failed", "message": f"Shutdown failed: {output}"})
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Shutdown failed for {vm.name}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


def is_online(ip):
    """Checks if a VM is online via ping."""
    try:
        # Use ping -c 1 -W 1 for faster timeout, suppress output
        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return result.returncode == 0
    except Exception as e:
        print(f"Ping check failed for {ip}: {e}")
        return False
@main.route('/active-vms')
@login_required
def get_vm_status():
    all_vms = VM.query.all()
    status_dict = {}

    def check_and_update_vm_status(vm_obj):
        """Helper to check individual VM status and update dictionary."""
        # First, prioritize the status stored in the database if it's 'monitoring'
        if vm_obj.status == 'monitoring':
            status_dict[vm_obj.short_name] = "monitoring"
        else:
            # If not explicitly 'monitoring', then check network reachability
            is_vm_online = is_online(vm_obj.ip_address)
            if is_vm_online:
                status_dict[vm_obj.short_name] = "online"
            else:
                status_dict[vm_obj.short_name] = "offline"

    threads = []
    for vm_obj in all_vms:
        threads.append(Thread(target=check_and_update_vm_status, args=(vm_obj,)))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return jsonify(status_dict)