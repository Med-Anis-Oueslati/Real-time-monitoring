from flask import Blueprint, render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from .forms import SignUpForm, LoginForm

main = Blueprint('main', __name__)

# Dummy user store (in memory)
users = {}

@main.route('/')
def home():
    return render_template('landing.html')

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        if email in users:
            flash('Email already registered.', 'error')
        else:
            users[email] = generate_password_hash(form.password.data)
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('main.login'))
    return render_template('signup.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        user_hash = users.get(email)
        if user_hash and check_password_hash(user_hash, password):
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.html', form=form)
@main.route('/dashboard')
def dashboard():
    # Add login check if needed:
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    return render_template('dashboard.html')