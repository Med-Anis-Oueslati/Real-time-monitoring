from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField, TextAreaField, BooleanField
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
    submit = SubmitField('Logout')


class AddVMForm(FlaskForm):
    name = StringField('VM Name', validators=[DataRequired(), Length(min=2, max=64)])
    short_name = StringField('Short Name (e.g., kali, lubuntu)', validators=[
        DataRequired(),
        Length(min=2, max=32),
        Regexp('^[a-z0-9_]+$', message="Short name must be lowercase alphanumeric or underscore.")
    ])
    ip_address = StringField('IP Address', validators=[
        DataRequired(),
        Regexp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', message="Invalid IP address format")
    ])
    ssh_username = StringField('SSH Username', validators=[DataRequired(), Length(min=2, max=64)])
    ssh_password = PasswordField('SSH Password', validators=[Length(max=128)]) # Optional, not DataRequired
    description = TextAreaField('Description (Optional)', validators=[Length(max=256)])
    submit = SubmitField('Add VM')

class EditVMForm(FlaskForm):
    # Hidden field to store the VM's short_name for identification in AJAX
    vm_short_name = HiddenField('VM Short Name')
    name = StringField('VM Name', validators=[DataRequired(), Length(min=2, max=64)])
    # Short name is usually not editable as it's a unique identifier used internally
    # But for display consistency, we can include it as read-only or regenerate it if needed.
    # For now, let's keep it in the form for ease, but typically it wouldn't be directly edited.
    # We will get it from the hidden field 'vm_short_name'
    ip_address = StringField('IP Address', validators=[
        DataRequired(),
        Regexp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', message="Invalid IP address format")
    ])
    ssh_username = StringField('SSH Username', validators=[DataRequired(), Length(min=2, max=64)])
    ssh_password = PasswordField('SSH Password (leave blank to keep current)', validators=[Length(max=128)])
    description = TextAreaField('Description (Optional)', validators=[Length(max=256)])
    submit = SubmitField('Update VM')