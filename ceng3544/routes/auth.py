from base64 import b64encode
import datetime
from io import BytesIO
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import current_user, login_user, logout_user, login_required
import pyotp
import qrcode
from werkzeug.security import generate_password_hash

from ceng3544.models import Models
from ceng3544.webforms.login_form import LoginForm
from ceng3544.webforms.register_form import RegisterForm
from ceng3544 import Database

auth = Blueprint('auth', __name__)

@auth.route('/auth/admin', methods=['GET', 'POST'])
@login_required
def admin():
	if current_user.role != 'admin':
		flash('You do not have permission to access this page.', 'warning')
		return redirect(url_for('index'))
	users = Models.model.user_model.query.all()
	return render_template('auth/admin.html', users=users)

@auth.route('/auth/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()

	# Form is not filled
	if not form.validate_on_submit():
		return render_template('auth/login.html', form=form)
	
	# Check if username_or_email is email
	if '@' in form.username_or_email.data:
		user = Models.model.user_model.query.filter_by(email=form.username_or_email.data).first()
	else:
		user = Models.model.user_model.query.filter_by(username=form.username_or_email.data).first()

	if not user or not user.verify_password(form.password.data):
		flash('Invalid email or password.', 'danger')
		return redirect(url_for('auth.login'))
	
	# Challenge
	if form.challenge_select.data == 'email':
		user.email_verify_token_create()
		Database.db.session.commit()

		# TODO: Actually sent email
		# send_email(user.email, 'Login Challenge', f'Click the link to login: {url_for("auth.login_challenge_email", user_id=user.id, code=user.email_verify_token, _external=True)}')

		flash('Email sent successfully.', 'success')
		return render_template('auth/login_challenge_email.html', user_id=user.id, email_token=user.email_verify_token)

	if form.challenge_select.data == 'otp':
		return render_template('auth/login_challenge_otp.html', user_id=user.id)
	
	if form.challenge_select.data == 'qr':
		user.qr_approved_code_create()
		Database.db.session.commit()
		base64_qr_image = get_b64encoded_qr_image(user.qr_approved_code)
		return render_template('auth/login_challenge_qr.html', user_id=user.id, secret=user.qr_approved_code, qr_image=base64_qr_image)

	# Login
	# login_user(user)
	# flash('Logged in successfully.', 'success')
	# return render_template('auth/login_challenge.html', user_id=user.id, email_token=user.email_verify_token)

# Login Challenge With Email
@auth.route('/auth/login/challenge/email/<int:user_id>/<code>')
def login_challenge_email(user_id, code):
	user = Models.model.user_model.query.get(user_id)
	timenow = datetime.datetime.utcnow()

	if not user or not user.email_verify_token == code or not user.email_verify_token_expire > timenow:
		flash('Invalid challenge code.', 'danger')
		return redirect(url_for('auth.login'))
	login_user(user)
	flash('Logged in successfully.', 'success')
	return redirect(url_for('index'))

# Login Challenge With OTP
@auth.route('/auth/login/challenge/otp/<int:user_id>', methods=['POST'])
def login_challenge_otp(user_id):
	user = Models.model.user_model.query.get(user_id)
	timenow = datetime.datetime.utcnow()
	
	if not user or not user.is_2fa_enabled:
		flash('Invalid challenge code.', 'danger')
		return redirect(url_for('auth.login'))
	
	if not pyotp.TOTP(user.secret_token).verify(request.form['otp']):
		flash('Invalid challenge code.', 'danger')
		return redirect(url_for('auth.login'))
	
	login_user(user)
	flash('Logged in successfully.', 'success')
	return redirect(url_for('index'))

# Login Challenge With QR Code
@auth.route('/auth/login/challenge/qr/', methods=['GET'])
def login_challenge_qr():
	user_id = request.args.get('user_id')
	code = request.args.get('amp;code')

	# Debug
	print(user_id)
	print(code)

	user = Models.model.user_model.query.get(user_id)
	timenow = datetime.datetime.utcnow()

	if not user or not user.qr_approved_code == code or not user.qr_approved_code_expire > timenow or not user.qr_approved or user.qr_used:
		return 'Invalid challenge code.', 400
	login_user(user)
	user.qr_used = True
	Database.db.session.commit()
	flash('Logged in successfully.', 'success')
	return 'Logged in successfully.', 200

@auth.route('/auth/logout')
@login_required
def logout():
	logout_user()
	flash('Logged out successfully.', 'success')
	return redirect(url_for('auth.login'))

@auth.route('/auth/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm()

	# Form is not filled
	if not form.validate_on_submit():
		return render_template('auth/register.html', form=form)
	
	# Check if user already exists
	if check_user_email(form.email.data):
		flash('This email is already registered.', 'warning')
		return redirect(url_for('auth.register'))
	if check_user_username(form.username.data):
		flash('This username is already registered.', 'warning')
		return redirect(url_for('auth.register'))
	
	# Check confirmation password
	if form.password.data != form.confirm_password.data:
		flash('Password and confirmation password do not match.', 'warning')
		return redirect(url_for('auth.register'))
	
	# Register
	user = Models.model.user_model(
		name=form.name.data,
		username=form.username.data,
		email=form.email.data,
		password_hash=generate_password_hash(form.password.data),
		role='user'
	)
	Database.db.session.add(user)
	Database.db.session.commit()
	flash('User added successfully.', 'success')
	return redirect(url_for('auth.login'))

@auth.route('/auth/setup', methods=['GET', 'POST'])
def setup():
	if Models.model.user_model.query.count() > 0:
		return redirect(url_for('auth.login'))
	form = RegisterForm()

	# Form is not filled
	if not form.validate_on_submit():
		return render_template('auth/setup.html', form=form)
	
	# Check if user already exists
	if check_user_email(form.email.data):
		flash('This email is already registered.', 'warning')
		return redirect(url_for('auth.setup'))
	if check_user_username(form.username.data):
		flash('This username is already registered.', 'warning')
		return redirect(url_for('auth.setup'))
	
	# Check confirmation password
	if form.password.data != form.confirm_password.data:
		flash('Password and confirmation password do not match.', 'warning')
		return redirect(url_for('auth.setup'))
	
	# Register
	user = Models.model.user_model(
		name=form.name.data,
		username=form.username.data,
		email=form.email.data,
		password_hash=generate_password_hash(form.password.data),
		role='admin'
	)
	Database.db.session.add(user)
	Database.db.session.commit()
	flash('Admin added successfully.', 'success')
	return redirect(url_for('auth.login'))

def check_user_username(data):
	if Models.model.user_model.query.filter_by(username=data).first():
		return True
	return False

def check_user_email(data):
	if Models.model.user_model.query.filter_by(email=data).first():
		return True
	return False

@auth.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
	return render_template('auth/profile.html')

def get_b64encoded_qr_image(data):
    print(data)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

@auth.route('/profile/2fa', methods=['GET', 'POST'])
@login_required
def profile_2fa():

	# Check if 2fa is already enabled
	if current_user.is_2fa_enabled:

		# Disable 2FA - DEBUG
		current_user.is_2fa_enabled = False
		Database.db.session.commit()

		flash('2FA is already enabled.', 'warning')
		return redirect(url_for('auth.profile'))

	if request.method == 'GET':
		# Generate secret token
		if not current_user.secret_token:
			current_user.secret_token = pyotp.random_base32()
			Database.db.session.commit()

		# Generate QR Code
		otpauth_url = pyotp.totp.TOTP(current_user.secret_token).provisioning_uri(name=current_user.username, issuer_name='CENG3544 Project')
		base64_qr_image = get_b64encoded_qr_image(otpauth_url)
		return render_template('auth/profile_2fa.html', secret=current_user.secret_token, qr_image=base64_qr_image)
	
	if request.method == 'POST':
		# Check if OTP is correct
		if not pyotp.TOTP(current_user.secret_token).verify(request.form['otp']):
			flash('Invalid OTP.', 'danger')
			return redirect(url_for('auth.profile_2fa'))
		
		# Enable 2FA
		current_user.is_2fa_enabled = True
		Database.db.session.commit()
		flash('2FA enabled successfully.', 'success')
		return redirect(url_for('auth.profile'))
	
@auth.route('/profile/qr', methods=['GET', 'POST'])
@login_required
def profile_qr():
	if request.method == 'GET':
		return render_template('auth/profile_qr.html')

	if request.method == 'POST':
		if current_user.qr_approved_code != request.form['qr']:
			flash('Invalid code.', 'danger')
			return redirect(url_for('auth.profile_qr'))
		
		current_user.qr_approved = True
		Database.db.session.commit()
		flash('QR Code approved successfully.', 'success')
		return redirect(url_for('auth.profile'))
		
	

@auth.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def profile_change_password():
	form = RegisterForm()

	# Form is not filled
	if request.method == 'GET':
		return render_template('auth/profile_change_password.html', form=form)
	
	# Check old password
	if not Models.model.user_model.query.filter_by(id=current_user.id).first().verify_password(form.password.data):
		flash('Invalid old password.', 'danger')
		return redirect(url_for('auth.profile_change_password'))
	
	# Check if new password and confirmation password same
	if form.password.data == form.confirm_password.data:
		flash('Nothing to change.', 'warning')
		return redirect(url_for('auth.profile_change_password'))
	
	# Update password
	Models.model.user_model.query.filter_by(id=current_user.id).update({'password_hash': generate_password_hash(form.confirm_password.data)})
	Database.db.session.commit()
	flash('Password updated successfully.', 'success')
	return redirect(url_for('auth.profile'))

@auth.route('/profile/delete', methods=['GET', 'POST'])
@login_required
def profile_delete():

	if request.method == 'GET':
		
		if current_user.role != 'admin':
			return render_template('auth/profile_delete.html')
		
		# If admin, delete user with given id
		if request.args.get('id'):
			user = Models.model.user_model.query.get(request.args.get('id'))
			if user:
				Database.db.session.delete(user)
				Database.db.session.commit()
				flash('User deleted successfully.', 'success')
				return redirect(url_for('auth.admin'))
			flash('User not found.', 'danger')
			return redirect(url_for('auth.admin'))

	# Check confirmation password
	if not current_user.verify_password(request.form['password']):
		flash('Invalid password.', 'danger')
		return redirect(url_for('auth.profile_delete'))

	Database.db.session.delete(current_user)
	Database.db.session.commit()
	flash('User deleted successfully.', 'success')
	return redirect(url_for('auth.login'))

@auth.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit():
	form = RegisterForm()
	if current_user.role == 'admin':
		user = Models.model.user_model.query.get(request.args.get('id'))
		if not user:
			flash('User not found.', 'danger')
			return redirect(url_for('auth.admin'))
	else:
		user = current_user

	# Form is not filled
	if request.method == 'GET':
		form.name.data = user.name
		form.username.data = user.username
		form.email.data = user.email
		return render_template('auth/profile_edit.html', form=form)

	# Check if another user with same email or username exists
	if check_user_email(form.email.data) and form.email.data != user.email:
		flash('This email is already used.', 'warning')
		return redirect(url_for('auth.profile_edit'))
	if check_user_username(form.username.data) and form.username.data != user.username:
		flash('This username is already used.', 'warning')
		return redirect(url_for('auth.profile_edit'))
	
	# Check confirmation password if not admin
	if current_user.role != 'admin':
		if not user.verify_password(form.password.data):
			flash('Invalid password.', 'danger')
			return redirect(url_for('auth.profile_edit'))
	else:
		# If filled, change the password too
		if form.password.data:
			user.password_hash = generate_password_hash(form.password.data)
	
	# Update user
	user.name = form.name.data
	user.username = form.username.data
	user.email = form.email.data
	Database.db.session.commit()
	flash('User updated successfully.', 'success')
	return redirect(url_for('auth.profile'))