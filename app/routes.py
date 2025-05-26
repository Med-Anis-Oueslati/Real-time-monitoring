from flask import Blueprint, render_template, redirect, url_for, flash, request, session,jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms  import SignUpForm, LoginForm, LogoutForm
from .models import User
from . import db
import subprocess
import time
import requests
import paramiko
from . import csrf

main = Blueprint('main', __name__)

# Dummy user store (in memory)
users = {}

@main.route('/')
def home():
    return render_template('landing.html')

@main.route('/signup', methods=['GET', 'POST'])
def signup():
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
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.email
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.html', form=form)
@main.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    user = User.query.filter_by(email=session['user_id']).first()
    logout_form = LogoutForm()
    return render_template('dashboard.html', user=user, logout_form=logout_form)

@main.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.home'))


def is_streamlit_running():
    try:
        r = requests.get("http://localhost:8501")
        return r.status_code == 200
    except requests.ConnectionError:
        return False

@main.route('/start-streamlit', methods=['POST'])
def start_streamlit():
    if is_streamlit_running():
        return jsonify({"status": "already_running"})

    command = ["streamlit", "run", "/home/anis/PFE/agents/conversational_chatbot.py"]
    subprocess.Popen(command)
    time.sleep(2)

    if is_streamlit_running():
        return jsonify({"status": "started"})
    else:
        return jsonify({"status": "failed"})

# ✅ Exempt it from CSRF protection
csrf.exempt(start_streamlit)


@main.route("/vm-monitoring")
def vm_monitoring():
    return render_template("vm_monitoring.html")

def execute_commands_on_vm(ip, username, password):
    try:
        print(f"Connecting to {ip} with user {username}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)
        print("✅ SSH connected")

        ssh.exec_command("sudo /opt/zeek/bin/zeekctl deploy")
        time.sleep(5)
        ssh.exec_command("sudo fluentd -c /etc/fluentd.conf -v")

        ssh.close()
        print("✅ Commands executed successfully")
        return True
    except Exception as e:
        print(f"[SSH ERROR] {e}")
        return False

@main.route("/start-monitoring", methods=["POST"])
@csrf.exempt
def start_monitoring():
    print("📥 Received request to /start-monitoring")

    data = request.get_json()
    print(f"➡️  Parsed JSON: {data}")

    vm = data.get("vm")
    print(f"🖥️  VM requested: {vm}")

    try:
        if vm == "lubuntu":
            print("🔧 Starting Lubuntu monitoring...")
            success = execute_commands_on_vm("10.71.0.162", "anis", "root")
        elif vm == "kali":
            print("🔧 Starting Kali monitoring...")
            success = execute_commands_on_vm("10.71.0.120", "kali", "kali")
        else:
            print("❌ Unknown VM")
            return jsonify({"status": "error", "message": "Unknown VM"}), 400

        print(f"✅ Command execution result: {success}")

        if success:
            return jsonify({"status": "started"})
        else:
            return jsonify({"status": "failed"})
    except Exception as e:
        print(f"[❗ ERROR] VM Start Failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
