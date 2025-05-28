from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp

class SignUpForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class LogoutForm(FlaskForm):
    pass

# NEW: Form for editing VM IP
class EditVMForm(FlaskForm):
    # Regexp validator for basic IP validation (IPv4 format)
    ip_address = StringField('New IP Address', validators=[
        DataRequired(),
        Regexp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', message="Invalid IP address format (e.g., 192.168.1.1)")
    ])
    submit = SubmitField('Update IP')
