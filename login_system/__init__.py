#!/usr/bin/env python3
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from login_system import config

import os

app = Flask(__name__)


def load_config(app_mode):
    """Helper function to load the proper configuration for the application.

    :param app_mode: identifier to select the application configuration
    :type app_mode: str
    """

    if app_mode == "test":
        app.config.from_object(config.TestConfig())

    elif app_mode == "development":
        app.config.from_object(config.DevelopmentConfig())

    elif app_mode == "production":
        app.config.from_object(config.ProductionConfig())


load_config(os.getenv("APP_MODE", default="production").lower())


# Initialize Flask Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "auth.login"

from login_system.blueprints.auth.routes import auth  # noqa
from login_system.blueprints.public.routes import public  # noqa
from login_system.blueprints.dashboard.routes import dashboard  # noqa

app.register_blueprint(auth, url_prefix="/auth")
app.register_blueprint(public)
app.register_blueprint(dashboard, url_prefix="/dashboard")
