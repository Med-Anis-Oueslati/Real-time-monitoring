from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager # Import LoginManager
from .forms import LogoutForm
from flask_socketio import SocketIO
import os

# NEW: Import MitigationUtility
from .mitigation_utils import MitigationUtility
# NEW: Import AttackAgent
from agents.cyber_attack import AttackAgent

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager() # Initialize LoginManager
socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    # It's highly recommended to use environment variables for SECRET_KEY in production
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "q;hsjdvb;khb23RkhvqsdqA23blqksdhvb213bkhsvdb")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/anis/PFE/instance/site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app) # Initialize Flask-Login with the app
    socketio.init_app(app)
    login_manager.login_view = 'main.login' # Set the login view for @login_required decorator

    from .models import User # Import User model here to avoid circular dependency with routes
    @login_manager.user_loader
    def load_user(user_id):
        # This function is called by Flask-Login to reload the user object
        # from the user ID stored in the session.
        return User.query.get(int(user_id))

    # Initialize MitigationUtility and attach it to the app object
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    
    if not OPENAI_API_KEY:
        print("WARNING: OPENAI_API_KEY environment variable not set. Mitigation agent functionality may be limited.")
        app.mitigation_utility = None
    else:
        try:
            app.mitigation_utility = MitigationUtility(openai_api_key=OPENAI_API_KEY)
            print("MitigationUtility initialized successfully and attached to app.")
        except Exception as e:
            print(f"Error initializing MitigationUtility: {e}")
            app.mitigation_utility = None

    # NEW: Initialize AttackAgent and attach it to the app object
    KALI_VM_IP = os.getenv("KALI_VM_IP")
    KALI_VM_USER = os.getenv("KALI_VM_USER")
    KALI_VM_PASSWORD = os.getenv("KALI_VM_PASSWORD")
    KALI_SCRIPT_DIR = os.getenv("KALI_SCRIPT_DIR", "/home/kali/scripts") # Default if not set

    if not all([OPENAI_API_KEY, KALI_VM_IP, KALI_VM_USER, KALI_VM_PASSWORD]):
        print("WARNING: Missing environment variables for AttackAgent (OPENAI_API_KEY, KALI_VM_IP, KALI_VM_USER, KALI_VM_PASSWORD). Attack simulation functionality may be limited.")
        app.attack_agent = None
    else:
        try:
            app.attack_agent = AttackAgent(
                openai_api_key=OPENAI_API_KEY,
                kali_vm_ip=KALI_VM_IP,
                kali_vm_user=KALI_VM_USER,
                kali_vm_password=KALI_VM_PASSWORD,
                script_dir=KALI_SCRIPT_DIR
            )
            print("AttackAgent initialized successfully and attached to app.")
        except Exception as e:
            print(f"Error initializing AttackAgent: {e}")
            app.attack_agent = None


    from .routes import main
    app.register_blueprint(main)

    @app.context_processor
    def inject_logout_form():
        # This context processor is still useful to inject the logout form globally
        return dict(logout_form=LogoutForm())

    return app
