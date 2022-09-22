#!/usr/bin/python3
from login_system.models import User
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

import string


def lowercase_pw_character_check(form, field):
    """Validator function to test for lowercase characters in a form.

    :param form: The form that this validator was passed to
    :type form: wtforms.form.Form
    :param field: The field that this validator will validate
    :type field: wtforms.fields.Field

    :raises ValidationError: Raises when no lowercase characters were found in field.data
    """

    lowercase = any([ele in field.data for ele in string.ascii_lowercase])
    if not lowercase:
        raise ValidationError("Your password must contain a lowercase character.")
    return


def uppercase_pw_character_check(form, field):
    """Validator function to test for uppercase characters in a form.

    :param form: The form that this validator was passed to
    :type form: wtforms.form.Form
    :param field: The field that this validator will validate
    :type field: wtforms.fields.Field

    :raises ValidationError: Raises when no uppercase characters were found in field.data
    """

    uppercase = any([ele in field.data for ele in string.ascii_uppercase])
    if not uppercase:
        raise ValidationError("Your password must contain a uppercase character.")
    return


def digits_pw_character_check(form, field):
    """Validator function to test for digits in a form.

    :param form: The form that this validator was passed to
    :type form: wtforms.form.Form
    :param field: The field that this validator will validate
    :type field: wtforms.fields.Field

    :raises ValidationError: Raises when no digits were found in field.data
    """

    digits = any([ele in field.data for ele in string.digits])
    if not digits:
        raise ValidationError("Your password must contain a number.")
    return


def special_characters_pw_character_check(form, field):
    """Validator function to test for special characters in a form.

    :param form: The form that this validator was passed to
    :type form: wtforms.form.Form
    :param field: The field that this validator will validate
    :type field: wtforms.fields.Field

    :raises ValidationError: Raises when no special characters were found in field.data
    """

    special_characters = any([ele in field.data for ele in string.punctuation])
    if not special_characters:
        raise ValidationError(f"Your password must contain at least one of the following characters: {string.punctuation}")
    return


class RegisterForm(FlaskForm):
    """Form class to register a user for the application."""

    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(),
                                                     Length(min=8),
                                                     lowercase_pw_character_check,
                                                     uppercase_pw_character_check,
                                                     digits_pw_character_check,
                                                     special_characters_pw_character_check
                                                     ])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        """Validation function to verify usernames don't collide.

        Checks that there are no users in the database with the username passed. If there is
        a user found, the username is invalid.

        :raises ValidationError: Raises when a user was found in the database with provided username
        """

        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("That username is taken. Please choose a different one.")

    def validate_email(self, email):
        """Validation function to verify emails don't collide.

        Checks that there are no users in the database with the email passed. If there is
        a user found, the email is invalid.

        :raises ValidationError: Raises when a user was found in the database with provided email
        """

        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError("That email address is already registered. Please login or choose a different email.")


class ResetRequestForm(FlaskForm):
    """Form class to request a password reset."""

    identifier = StringField("Username or Email", validators=[DataRequired()])
    submit = SubmitField("Request Password Reset")


class PasswordResetForm(FlaskForm):
    """Form class to change a users password."""

    password = PasswordField("New Password", validators=[DataRequired(),
                                                         Length(min=8),
                                                         lowercase_pw_character_check,
                                                         uppercase_pw_character_check,
                                                         digits_pw_character_check,
                                                         special_characters_pw_character_check
                                                         ])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
    reset_password = SubmitField("Reset Password")


class LoginForm(FlaskForm):
    """Form class to login a user."""

    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me", default=False)
    submit = SubmitField("Login")
