from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from .forms import LogoutForm
import os
db = SQLAlchemy()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = "q;hsjdvb;khb23RkhvqsdqA23blqksdhvb213bkhsvdb"
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    csrf.init_app(app)

    from .routes import main
    app.register_blueprint(main)
    @app.context_processor
    def inject_logout_form():
        return dict(logout_form=LogoutForm())

    return app
