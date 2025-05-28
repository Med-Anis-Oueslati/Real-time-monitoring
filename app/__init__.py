from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager # Import LoginManager
from .forms import LogoutForm
import os

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager() # Initialize LoginManager

def create_app():
    app = Flask(__name__)
    # It's highly recommended to use environment variables for SECRET_KEY in production
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "q;hsjdvb;khb23RkhvqsdqA23blqksdhvb213bkhsvdb")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app) # Initialize Flask-Login with the app
    login_manager.login_view = 'main.login' # Set the login view for @login_required decorator

    from .models import User # Import User model here to avoid circular dependency with routes
    @login_manager.user_loader
    def load_user(user_id):
        # This function is called by Flask-Login to reload the user object
        # from the user ID stored in the session.
        return User.query.get(int(user_id))

    from .routes import main
    app.register_blueprint(main)

    @app.context_processor
    def inject_logout_form():
        # This context processor is still useful to inject the logout form globally
        return dict(logout_form=LogoutForm())

    return app