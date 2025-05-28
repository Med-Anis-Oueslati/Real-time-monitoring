# run.py
from app import create_app, db
import sys
import os
from app.models import VM # Import the new VM model

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'agents')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates all tables including the new VM table

        # --- Populate initial VM data if tables are empty ---
        if not VM.query.first():
            print("Populating initial VM data...")
            lubuntu_vm = VM(
                short_name='lubuntu',
                name='Lubuntu VM',
                ip_address='172.20.10.5',
                ssh_username='anis',
                ssh_password='root', # CRITICAL: Secure this in production!
                status='offline'
            )
            kali_vm = VM(
                short_name='kali',
                name='Kali Linux VM',
                ip_address='172.20.10.4',
                ssh_username='kali',
                ssh_password='kali', # CRITICAL: Secure this in production!
                status='offline'
            )
            db.session.add(lubuntu_vm)
            db.session.add(kali_vm)
            db.session.commit()
            print("Initial VM data populated.")
        # ----------------------------------------------------

    app.run(debug=True)