from datetime import datetime
from . import db
from flask_login import UserMixin # Import UserMixin

class User(db.Model, UserMixin): # Inherit from UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    

# New VM Model (Ensure this matches or update accordingly)
class VM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False) # e.g., "Lubuntu VM"
    # MODIFIED: Removed unique=True constraint
    short_name = db.Column(db.String(32), nullable=False) # e.g., "lubuntu", "kali"
    ip_address = db.Column(db.String(15), nullable=False) # IPv4 format
    ssh_username = db.Column(db.String(64), nullable=False)
    # WARNING: Storing plain passwords is not secure for production!
    # Consider using ssh_key_path and ssh_key_passphrase instead.
    ssh_password = db.Column(db.String(128), nullable=True) # Optional if using keys
    description = db.Column(db.String(256), nullable=True) # e.g., "My primary analysis VM"
    status = db.Column(db.String(32), default='offline', nullable=False) # e.g., 'online', 'offline', 'monitoring'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Link to the user who owns it


    def __repr__(self):
        return f'<VM {self.name} ({self.ip_address})>'