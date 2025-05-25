from app import create_app, db  # Replace 'yourpackage' with your actual package name
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'agents')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)