#!/usr/bin/env python3
from flask import url_for, flash, redirect
from flask_login import login_required, current_user, logout_user

from login_system import app
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

import datetime
import jwt
import smtplib


def send_reset_email(user):
    """Utility function to generate the reset email.

    :param user: The user model to send the reset email to
    :type user: models.User

    :return: The generated message body that would be send to the user.
    :rtype: string

    :raises RuntimeError: Raises when the message could not be sent.

    Generate a password reset token and place it in the message body template. Also generate
        the url for the user to click and place it in the message body template. Send the message
        body to the send_email utility.
    """
    token = create_token({"user_id": user.id, "request": "password_reset"})
    subject = "Password Reset Request"

    msg_body = f"""Hi {user.username}

To reset your password, visit the following link:
{url_for('auth.reset_password', token=token, _external=True)}

This link will expire in 30 minutes.

If you did not make this request, then simply ignore this email and no changes will be made.
"""

    try:
        message = send_email(user, subject, msg_body)
    except RuntimeError:
        raise RuntimeError
    return message


def send_email_confirmation(user):
    """Utility function to generate the address confirmation email.

    :param user: The user model to send the confirmation email to
    :type user: models.User

    :return: The generated message body that would be send to the user.
    :rtype: string

    :raises RuntimeError: Raises when the message could not be sent.

    Generate an address confirmation token and place it in the message body template. Also generate
        the url for the user to click and place it in the message body template. Generate a token
        to report the email address and place it in the message body template. Send the message body
        to the send_email utility.
    """
    token = create_token({"user_id": user.id, "email": user.email, "request": "email_confirmation"})
    report_token = create_token({"user_id": user.id, "email": user.email, "request": "report_email"}, expires_sec=60 * 60 * 24 * 14)  # 14 Days expiration
    subject = "Email Confirmation"
    msg_body = f"""Hi {user.username}
To confirm your email address, visit the following link:
{url_for('auth.confirm_email', token=token, _external=True)}

This link will expire in 30 minutes.

If you did not create an account for this service, please use the following link to report this email and disable the account trying to use your email address:
{url_for('auth.report_email_confirmation', token=report_token, _external=True)}

This link will expire in 14 days.
"""

    try:
        message = send_email(user, subject, msg_body)
    except RuntimeError:
        raise RuntimeError

    return message


def send_email(user, subject, msg_body):
    """Helper utility to build and send emails.

    This utility handles creating the email into the proper form to be sent using
    a MIMEMultipart type. It will also handle connecting to the server and sending
    the email to the SMTP server.

    :param user: The user object that we want to send the email to
    :type user: models.User
    :param subject: The subject of the email
    :type subject: string
    :param msg_body: The body of the message
    :type msg_body: string

    :returns: Email data that was sent
    :rtype: string

    :raises RuntimeError: Raises when there is an issue sending the email
    """

    msg = MIMEMultipart()
    msg.attach(MIMEText(msg_body))
    msg["From"] = f"{app.config['MAIL_DISPLAY_NAME']} <{app.config['MAIL_USERNAME']}>"
    msg["To"] = user.email
    msg["Subject"] = subject

    try:
        with smtplib.SMTP_SSL(app.config["MAIL_SERVER"], app.config["MAIL_PORT"]) as server:
            server.ehlo()
            server.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
            server.sendmail(app.config["MAIL_USERNAME"], user.email, msg.as_string())

    # We don't really care about the type of exception that was raised, we just need to
    #   let the user know that some kind of error occured. We pass the type and error
    #   string along so we can log it later on.
    except Exception as e:
        msg = f"{type(e)}: {str(e)}"
        raise RuntimeError(msg)

    return msg.as_string()


def create_token(data, expires_sec=1800):
    """Utility to create a JSONWebToken.

    This utility deals with the signing and expiration details automatically
    and encodes it with an HS256 algorithm. If expires_sec is set to 0, no expiration
    time is set.

    :param data: Dictionary of data to encode in the token
    :type data: dict
    :param expires_sec: Time in seconds before the token expires. Defaults to 1800 seconds (30 minutes)
    :type expires_sec: int

    :returns: The token that was generated
    :rtype: string
    """

    token_data = data
    if expires_sec != 0:
        token_data["exp"] = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=expires_sec)
    token = jwt.encode(
        token_data,
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )
    return token


def verify_token(token, leeway=60):
    """Utility to verify a JSONWebToken.

    This utility verifies that the data has not been tampered with and that the token
    is still within it's verification time.

    :param token: Token (generated by `create_token`) to verify
    :type token: string
    :param leeway: Time in seconds where the token will still be verified after the time expires. Defaults to 60 seconds.
    :type leeway: integer

    :returns: The data that was passed with the token creation or None if the token was expired or invalid.
    :rtype: dictionary OR None
    """

    try:
        data = jwt.decode(
            token,
            app.config["SECRET_KEY"],
            leeway=datetime.timedelta(seconds=leeway),
            algorithms=["HS256"]
        )
    except:  # noqa
        return None

    return data


def authorized(func):
    """Function decorator to verify a user is logged in and is not disabled.

    This is a wrapper around the login_required decorator to also check to
    make sure the current user is enabled. If the user is disabled, log the
    user out, flash a message for the user and redirect them to the index page.

    :param func: - The function wrap this decorator around
    """

    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        """Verifies that the user is enabled. If the user is disabled, redirects the
            user to the index page with a message indicating that their account is disabled.
        """
        if not current_user.enabled:
            logout_user()
            flash("Your account is disabled.", "error")
            return redirect(url_for("public.index"))
        return func(*args, **kwargs)

    return wrapper
