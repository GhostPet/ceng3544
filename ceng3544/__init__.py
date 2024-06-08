import os

from flask import Flask, redirect, render_template, url_for
from dotenv import load_dotenv
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from ceng3544.models import Models

# Create Application
def create_app():
	load_dotenv()
	app = Flask(__name__, instance_relative_config=True)
	app.config.from_mapping(
		SECRET_KEY=os.getenv('SECRET_KEY', default='dev'),
		SQLALCHEMY_DATABASE_URI=os.getenv('SQLALCHEMY_DATABASE_URI', default='sqlite:///mangapet.db'),
		SQLALCHEMY_TRACK_MODIFICATIONS=False,
		UPLOAD_FOLDER=os.getenv('UPLOAD_FOLDER', default='uploads'),
	)

	with app.app_context():
		Database(app).init_db()

	# Route Blueprints
	from ceng3544.routes import auth, errors
	app.register_blueprint(auth.auth)
	app.register_blueprint(errors.errors)

	## Login Manager
	login_manager = LoginManager()
	login_manager.init_app(app)
	login_manager.login_view = 'auth.login'

	@login_manager.user_loader
	def load_user(user_id):
		return Models.model.user_model.query.get(int(user_id))
	
	# Default Routes
	@app.route('/')
	def index():
		if Models.model.user_model.query.count() == 0:
			return redirect(url_for('auth.setup'))
		return render_template('index.html')

	@app.context_processor
	def base_context():
		title = 'CENG3544 Project'
		return dict(title=title)

	return app

class Database:
	db = None
	migrate = None

	def __init__(self, app):
		self.db = SQLAlchemy(app)
		self.migrate = Migrate(app, self.db)
		Database.db = self.db
		Database.migrate = self.migrate

	def init_db(self):
		Models(self.db)
		self.db.create_all()