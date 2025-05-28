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
    

class VM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # A unique identifier for the VM (e.g., 'lubuntu-vm', 'kali-linux-vm')
    # This will be used as the 'vm' parameter in your AJAX calls
    short_name = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False) # Display name like "Lubuntu VM"
    ip_address = db.Column(db.String(15), nullable=False)
    ssh_username = db.Column(db.String(50), nullable=False)
    # Store SSH password securely (e.g., encrypted or via SSH keys).
    # For this example, we'll keep it simple for now, but acknowledge the security risk.
    ssh_password = db.Column(db.String(100), nullable=False) # Or path to SSH key
    status = db.Column(db.String(20), default='offline', nullable=False) # 'online', 'offline', 'monitoring'
    # Optional: link to a user if VMs are user-specific
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # user = db.relationship('User', backref='vms')