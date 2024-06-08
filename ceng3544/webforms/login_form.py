from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
	username_or_email = StringField('Username or Email', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	challenge_select = SelectField('Challenge Select', validators=[DataRequired()], choices=[('email', 'Email'), ('otp', 'OTP'), ('qr', 'QR Code')])
	submit = SubmitField('Login')