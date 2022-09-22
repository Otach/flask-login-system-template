#!/usr/bin/env python3
from login_system import models, db
import login_system.blueprints.auth.forms as forms
from login_system.blueprints.auth.utils import verify_token, authorized, send_email_confirmation, send_reset_email

import werkzeug

from flask import Blueprint, redirect, url_for, render_template, flash, request
from flask_login import logout_user, current_user, login_user
from uuid import uuid4

auth = Blueprint("auth", __name__)


@auth.route("/register", methods=["GET", "POST"])
def register():
    """Route to handle user registration.

    On a GET request:
        Render the register.html template with the register form.

    On a POST request:
        Validate the register form and add the new user and profile
            to the database. Redirects the user to the login form.

        If the form is not valid, render the register.html form with the errors for the form.
    """

    register_form = forms.RegisterForm()

    if register_form.validate_on_submit():
        hashed_password = werkzeug.security.generate_password_hash(register_form.password.data)
        new_user = models.User(
            id=str(uuid4()),
            username=register_form.username.data,
            email=register_form.email.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration was successful!", 'message')
        return redirect(url_for("auth.login"))

    return render_template("register.html", register_form=register_form, login_redirect=True)


@auth.route("/login", methods=["GET", "POST"])
def login():
    """Route to handle user login.

    On all requests, check to see if the user is authenticated. If they are authenticated,
    redirect the user to the dashboard.

    On GET requests:
        Render the login.html template with the login form.

    On POST requests:
        Validate the login form, log the user in, and redirect the user to the dashboard.

        If the form is not valid, render the login.html page with the error from the login form.

        If the password is incorrect or the user does not exist, render the login.html template with
            an invalid username or password message.

        If the password is correct but the user account is disabled, redirect the user to the index
            page with a message stating the account is disabled.
    """

    if current_user.is_authenticated:
        flash("You have been logged in.")
        return redirect(url_for('dashboard.dashboard_index'))

    login_form = forms.LoginForm()

    if login_form.validate_on_submit():
        user = models.User.query.filter_by(username=login_form.username.data).first()
        if user and werkzeug.security.check_password_hash(user.password, login_form.password.data):

            if not user.enabled:
                flash("Your account is disabled.", "error")
                return redirect(url_for("public.index"))

            login_user(user, remember=login_form.remember_me.data)
            flash("Log in Successful!", "message")
            next_page = request.args.get("next")
            return redirect(next_page) if next_page else redirect(url_for('dashboard.dashboard_index'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template("login.html", login_form=login_form)


@auth.route("/logout", methods=['GET'])
@authorized
def logout():
    """Route to handle user logouts and redirects to the index page."""

    logout_user()
    return redirect(url_for("public.index"))


@auth.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    """Route to handle password reset requests.

    On all requests, check to see if the user is authenticated. If they are authenticated,
    redirect the user to the dashboard.

    On GET requests:
        Render the forgot_password.html template with the password reset request form.

    On POST requests:
        Get the user model and pass the user object to the send_reset_email utility to send the
            email. Redirect the user to the login page with a message indicating that an email
            will be sent.

        If there is an issue sending the email, render the forgot_password.html template with
            a message telling the user to try again because there was an issue.

        If the user does not exist, still redirect the user to the login page with a message indicating
            that an email will be sent if there is a matching email address on record.
    """

    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_index"))

    request_form = forms.ResetRequestForm()

    if request_form.validate_on_submit():
        user = models.User.get_by_identifier(request_form.identifier.data)
        if user:
            try:
                send_reset_email(user)
            except RuntimeError:
                flash("An error occurred trying to send the email. Please try again later.", "error")
                return redirect(url_for("auth.forgot_password"))

        flash("Password reset link will be sent to your email if we have one on record.", "message")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html", form=request_form)


@auth.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Route to handle the password reset functionality.

    On all requests:
        Check to see if the user is authenticated. If they are authenticated, redirect the
            user to the dashboard.

        Verify the validity of the token.
            If the token is not valid, redirect the user to the forgot password page with a message
                stating the token is invalid or expired.

        Verify this token is for password resets.
            If the token is not for password resets, redirect the user to the forgot password page
                with a message stating the token is invalid.

        Verify that the user provided exists.
            If the user doesn't exist, redirect the user to the forgot password page
                with a message stating the token is invalid or expired.

        Verify that the user is not disabled.
            If the user is disabled, redirect the user to the index page with a message stating
                that their user account is disabled.

    On GET requests:
        Render the password_reset.html template with the password reset form.

    On POST requests
        Validate the password reset form and update the user model with the provided password. Redirects
            the user to the login page with a message indicating that the password has been updated.
    """

    if current_user.is_authenticated:
        flash("You have been logged in.")
        return redirect(url_for("dashboard.dashboard_index"))

    token_data = verify_token(token)
    if token_data is None:
        flash("Invalid or Expired reset token.", "error")
        return redirect(url_for("auth.forgot_password"))

    try:
        if token_data["request"] != "password_reset":
            flash("Invalid or Expired reset token.", "error")
            return redirect(url_for("auth.forgot_password"))

        user = models.User.query.filter_by(id=token_data["user_id"]).first()

    except KeyError:
        flash("Invalid reset token.", "error")
        return redirect(url_for("auth.forgot_password"))

    if not user:
        flash("Invalid or Expired reset token.", "error")
        return redirect(url_for("auth.forgot_password"))

    if not user.enabled:
        flash("Your account is disabled.", "error")
        return redirect(url_for("public.index"))

    form = forms.PasswordResetForm()
    if form.validate_on_submit():
        hashed_password = werkzeug.security.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been updated. You are now able to log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("password_reset.html", form=form)


@auth.route("/confirm_email_request")
@authorized
def confirm_email_request():
    """Route to handle email confirmation requests.

    Check to see if the user's email address is validated. If the address is already validated,
        redirect the user to the dashboard with a message stating the address is already confirmed.

    Passes the current_user object to the send_email_confirmation utility to send an email
        to the user with a time-based token.

    Redirects the user to the dashboard with a message stating the confirmation email has been sent.

    If there is an issue with sending the email, redirect the user to the dashboard with a message
        stating there was an issue sending the email and to try again later.
    """

    if current_user.email_validated:
        flash("Your email address is already confirmed.")
        return redirect(url_for("dashboard.dashboard_index"))

    try:
        send_email_confirmation(current_user)
    except RuntimeError:
        flash("An error occurred trying to send the email. Please try again later.", "error")
        return redirect(url_for("dashboard.dashboard_index"))

    flash("Confirmation email sent.", "message")
    return redirect(url_for("dashboard.dashboard_index"))


@auth.route("/confirm_email/<token>")
@authorized
def confirm_email(token):
    """Route to handle the email confirmation functionality.

    On all requests:
        Verify the validity of the token.
            If the token is not valid, redirect the user to the dashboard with a message
                stating the token is invalid or expired.

        Verify this token is for email confirmations.
            If the token is not for email confirmations, redirect the user to the dashboard
                with a message stating the token is invalid.

        Verify the token has the data for the current user.
            If the token does not have the current user data, redirect to the dashboard with
                a message stating the token is invalid.

        Verify the token has the required data.
            If the required data is not in the token, redirect to the dashboard and flash a
                message saying the token is invalid.

        Update the user model to show a validated email and redirect to the dashboard with
            a message stating the email has been confirmed.
    """
    token_data = verify_token(token)
    if token_data is None:
        flash("Invalid or Expired confirmation token.", "error")
        return redirect(url_for("dashboard.dashboard_index"))

    try:
        if token_data["user_id"] != current_user.id:
            flash("Invalid confirmation token.", "error")
            return redirect(url_for("dashboard.dashboard_index"))

        if token_data["email"] != current_user.email:
            flash("Invalid confirmation token.", "error")
            return redirect(url_for("dashboard.dashboard_index"))

        if token_data["request"] != "email_confirmation":
            flash("Invalid confirmation token.", "error")
            return redirect(url_for("dashboard.dashboard_index"))
    except KeyError:
        flash("Invalid Confirmation Token.", "error")
        return redirect(url_for("dashboard.dashboard_index"))

    current_user.email_validated = True
    db.session.commit()
    flash("Your email address has been confirmed.")
    return redirect(url_for("dashboard.dashboard_index"))


@auth.route("/report_confirmation/<token>")
def report_email_confirmation(token):
    """Route to handle email reporting functionality.

    Verify the token is valid.
        If the token is invalid, redirect the user to the index page with a message stating the
            token was invalid.

    Verify the token is for email reporting.
        If the token is not for reporting emails, redirect the user to the index page with a message
            stating the token is invalid.

    Verify that the user exists.
        If the user does not exist, redirect the user to the index page with a message stating
            that the user does not exist.

    Verify that the user and email match.
        If the user does not have the matching email address, redirect the user to the index page
            with a message static that the email does not match the user.

    Set the user account that was reported to a disabled state and redirect to the index page
        with a message indicating that the account with that email address was disabled.
    """
    token_data = verify_token(token)
    if token_data is None:
        flash("Invalid or Expired token.")
        return redirect(url_for('public.index'))

    try:
        if token_data["request"] != "report_email":
            flash("Invalid token. Token not for reporting emails.", "error")
            return redirect(url_for('public.index'))

        user = models.User.query.filter_by(id=token_data["user_id"]).first()
        if not user:
            flash("Invalid token. This user does not exist.", "error")
            return redirect(url_for("public.index"))

        if token_data["email"] != user.email:
            flash("Invalid token. Email does not match user.", "error")
            return redirect(url_for("public.index"))

    except KeyError:
        flash("Invalid Report Token.", "error")
        return redirect(url_for('public.index'))

    user.enabled = False
    db.session.commit()
    flash(f"The account associated with {token_data['email']} has been disabled.")
    return redirect(url_for('public.index'))
