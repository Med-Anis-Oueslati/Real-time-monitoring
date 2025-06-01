from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from .forms import LogoutForm
from flask_socketio import SocketIO
import os
import logging # Import logging

# NEW: Import MitigationUtility
from .mitigation_utils import MitigationUtility
# NEW: Import AttackAgent
from agents.cyber_attack import AttackAgent

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
socketio = SocketIO()

# Configure logging for __init__.py and other modules
logging.basicConfig(
    level=logging.INFO, # Set to INFO for normal operation
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Suppress verbose logging from third-party libraries ---
# Set to ERROR to only show critical errors, effectively suppressing most debug/info messages
logging.getLogger('watchdog.observers.inotify_buffer').setLevel(logging.ERROR)
logging.getLogger('httpcore.connection').setLevel(logging.ERROR)
logging.getLogger('httpcore.http11').setLevel(logging.ERROR)
logging.getLogger('httpx').setLevel(logging.ERROR)
logging.getLogger('openai._base_client').setLevel(logging.ERROR)
logging.getLogger('paramiko').setLevel(logging.ERROR) # Add paramiko if you see its debugs
# ---------------------------------------------------------


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "q;hsjdvb;khb23RkhvqsdqA23blqksdhvb213bkhsvdb")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/anis/PFE/instance/site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)

    app.socketio = socketio 

    login_manager.login_view = 'main.login'

    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    
    if not OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY environment variable not set. Mitigation agent functionality may be limited.")
        app.mitigation_utility = None
    else:
        try:
            app.mitigation_utility = MitigationUtility(openai_api_key=OPENAI_API_KEY)
            logger.info("MitigationUtility initialized successfully and attached to app.")
        except Exception as e:
            logger.error(f"Error initializing MitigationUtility: {e}", exc_info=True)
            app.mitigation_utility = None

    KALI_VM_IP = os.getenv("KALI_VM_IP")
    KALI_VM_USER = os.getenv("KALI_VM_USER")
    KALI_VM_PASSWORD = os.getenv("KALI_VM_PASSWORD")
    KALI_SCRIPT_DIR = os.getenv("KALI_SCRIPT_DIR", "/home/kali/scripts")

    if not all([OPENAI_API_KEY, KALI_VM_IP, KALI_VM_USER, KALI_VM_PASSWORD]):
        logger.warning("Missing environment variables for AttackAgent (OPENAI_API_KEY, KALI_VM_IP, KALI_VM_USER, KALI_VM_PASSWORD). Attack simulation functionality may be limited.")
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
            logger.info("AttackAgent initialized successfully and attached to app.")
        except Exception as e:
            logger.error(f"Error initializing AttackAgent: {e}", exc_info=True)
            app.attack_agent = None


    from .routes import main
    app.register_blueprint(main)

    @app.context_processor
    def inject_logout_form():
        return dict(logout_form=LogoutForm())

    return app
