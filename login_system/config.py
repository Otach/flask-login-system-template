#!/usr/bin/env python3
import os


class LoginSystemConfig():
    """Base Configuration for the login_system application."""

    SQLALCHEMY_DATABASE_URI = 'sqlite:///cipher.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_PORT = 465
    MAIL_SERVER = ""
    MAIL_USERNAME = ""
    MAIL_PASSWORD = ""
    MAIL_DISPLAY_NAME = ""
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class ProductionConfig(LoginSystemConfig):
    """Configuration for the Login System application for the production environment. Extends LoginSystemConfig."""

    SECRET_KEY = os.urandom(32)
    PRODUCTION = True
    SQLALCHEMY_DATABASE_URI = ''


class DevelopmentConfig(LoginSystemConfig):
    """Configuration for the Login System application for the development environment. Extends LoginSystemConfig."""

    SQLALCHEMY_DATABASE_URI = 'mysql://login_system_worker:dev_password@login-system-dev-db/login_system'
    DEBUG = True
    SECRET_KEY = "development_secret_key"
    DEVELOPMENT = True


class TestConfig(LoginSystemConfig):
    """Configuration for the Login System application for the testing and coverage environments. Extends LoginSystemConfig."""

    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "testing_secret_key"
    SERVER_NAME = "localhost.localdomain"
    APPLICATION_ROOT = "/"
    PREFERRED_URL_SCHEME = "http"
