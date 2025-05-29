# run.py
from app import create_app, db, socketio # MODIFIED: Import socketio
from app.models import User, VM
import os # NEW: Import os for environment variable
from dotenv import load_dotenv
load_dotenv() # Load environment variables from .env file
app = create_app()

with app.app_context():
    db.create_all()

    print("Populating initial VM data...")

    default_user = User.query.filter_by(username='admin').first()
    if not default_user:
        from werkzeug.security import generate_password_hash
        print("Creating default admin user...")
        default_user = User(username='admin', email='admin@example.com', password_hash=generate_password_hash('admin_password'))
        db.session.add(default_user)
        db.session.commit()
        print("Default admin user created.")
    else:
        print("Default admin user already exists.")

    if not VM.query.filter_by(short_name='lubuntu', user_id=default_user.id).first():
        print("Adding Lubuntu VM...")
        lubuntu_vm = VM(
            name='Lubuntu VM',
            short_name='lubuntu',
            ip_address='172.20.10.5',
            ssh_username='anis',
            ssh_password='root',
            description='My Lubuntu analysis VM',
            status='offline',
            user_id=default_user.id
        )
        db.session.add(lubuntu_vm)

    if not VM.query.filter_by(short_name='kali', user_id=default_user.id).first():
        print("Adding Kali VM...")
        kali_vm = VM(
            name='Kali VM',
            short_name='kali',
            ip_address='172.20.10.4',
            ssh_username='kali',
            ssh_password='kali',
            description='My Kali penetration testing VM',
            status='offline',
            user_id=default_user.id
        )
        db.session.add(kali_vm)

    try:
        db.session.commit()
        print("Initial VM data population complete.")
    except Exception as e:
        db.session.rollback()
        print(f"Error during VM data population: {e}")

if __name__ == '__main__':
    os.environ['FLASK_ENV'] = 'development'
    # MODIFIED: Use socketio.run instead of app.run
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True) # allow_unsafe_werkzeug for reloader with threads