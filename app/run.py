from flask import Flask
from flask_wtf.csrf import CSRFProtect
from .routes import main

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)

app.register_blueprint(main)

if __name__ == '__main__':
    app.run(debug=True)
