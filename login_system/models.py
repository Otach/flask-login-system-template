#!/usr/bin/env python3
from login_system import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    """Helper method for Flask-Login to load the user from the database."""

    return User.query.get(user_id)


class User(UserMixin, db.Model):
    """User database model class."""

    id = db.Column(db.CHAR(36), primary_key=True, nullable=False)
    username = db.Column(db.VARCHAR(64), nullable=False, unique=True)
    email = db.Column(db.VARCHAR(128), nullable=False, unique=True)
    password = db.Column(db.VARCHAR(102), nullable=False)
    email_validated = db.Column(db.Boolean, nullable=False, server_default="0")
    enabled = db.Column(db.Boolean, nullable=False, server_default="1")

    @staticmethod
    def get_by_identifier(identifier):
        """Method to get a user object from either a username or email.

        :param identifier: The username or email address of a user.
        :type identifier: string

        :return: The user object from the database OR None
        :rtype: login_system.model.User
        """

        user = User.get_by_username(identifier)
        if user:
            return user
        user = User.query.filter_by(email=identifier).first()
        if user:
            return user
        return None

    @staticmethod
    def get_by_username(username):
        """Method to get a user object from a username string.

        :param username: The username to search for
        :type username: string

        :return: The user object from the database OR None
        :rtype: login_system.model.User
        """
        return User.query.filter_by(username=username).first()
