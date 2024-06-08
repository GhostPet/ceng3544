import datetime
import os

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

def user_init(db):
	class User(db.Model, UserMixin):
		id = db.Column(db.Integer, primary_key=True)
		name = db.Column(db.String(80), nullable=False)
		username = db.Column(db.String(80), unique=True, nullable=False)
		email = db.Column(db.String(120), unique=True, nullable=False)
		password_hash = db.Column(db.String(255))
		role = db.Column(db.String(20), nullable=False)
		created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
		updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

		# Email Verification
		email_verify_token = db.Column(db.String(255))
		email_verify_token_expire = db.Column(db.DateTime)

		def email_verify_token_create(self):
			self.email_verify_token = os.urandom(16).hex()
			self.email_verify_token_expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)

		# One Time Password (OTP)
		is_2fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
		secret_token = db.Column(db.String(255), nullable=True)

		# Login with QR Code
		qr_approved_code = db.Column(db.String(255), nullable=True)
		qr_approved_code_expire = db.Column(db.DateTime)
		qr_approved = db.Column(db.Boolean, nullable=False, default=False)
		qr_used = db.Column(db.Boolean, nullable=False, default=False)

		def qr_approved_code_create(self):
			self.qr_approved_code = os.urandom(16).hex()
			self.qr_approved_code_expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
			self.qr_approved = False
			self.qr_used = False

		@property
		def password(self):
			raise AttributeError('Password is not a readable attribute.')
	
		@password.setter
		def password(self, password):
			self.password_hash = generate_password_hash(password)

		def verify_password(self, password):
			return check_password_hash(self.password_hash, password)

		def __repr__(self):
			return f'<User {self.username}>'

	return User