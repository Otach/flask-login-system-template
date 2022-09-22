#!/usr/bin/env python3
import unittest
import werkzeug
import wtforms

import login_system

from login_system import app, db, models
from login_system.blueprints.auth.utils import create_token

from unittest.mock import patch
from uuid import uuid4

TEST_USERNAME = "username"
TEST_EMAIL = "test@test.com"
TEST_PASSWORD = "P@ssw0rd!"  # nosec


class TestBase(unittest.TestCase):
    """Class for common methods used in this modules testing."""

    def setUp(self):
        """Helper code to setup the test client and create the database tables."""

        self.app = app.test_client()
        db.create_all()

    def tearDown(self):
        """Helper code to clean up after the tests by removing the database information."""

        db.session.remove()
        db.drop_all()

    def add_test_user(self, enabled=True, email_validated=False):
        """Adds a test user to the database to use in testing.

        :param enabled: Whether to set the user as enabled in the database. Defaults to True
        :type enabled: boolean
        :param email_validated: Whether to set the users email as validated. Defaults to False
        :type email_validated: boolean

        :returns: Returns the test user object
        :rtype: login_system.models.User
        """

        test_user = models.User(
            id=str(uuid4()),
            username=TEST_USERNAME,
            email=TEST_EMAIL,
            password=werkzeug.security.generate_password_hash(TEST_PASSWORD),
            enabled=enabled,
            email_validated=email_validated
        )
        db.session.add(test_user)
        db.session.commit()
        return self.get_test_user()

    def add_second_user(self, enabled=True, email_validated=False):
        """Adds a second test user to the database to use in testing.

        :param enabled: Whether to set the user as enabled in the database. Defaults to True
        :type enabled: boolean
        :param email_validated: Whether to set the users email as validated. Defaults to False
        :type email_validated: boolean

        :returns: Returns the test user object
        :rtype: login_system.models.User
        """
        test_user = models.User(
            id=str(uuid4()),
            username="user2",
            email="test2@test.com",
            password=werkzeug.security.generate_password_hash(TEST_PASSWORD),
            enabled=enabled,
            email_validated=email_validated
        )
        db.session.add(test_user)
        db.session.commit()
        return self.get_test_user(username="user2")

    def get_test_user(self, username=TEST_USERNAME):
        """Returns the test user from the database to use within testing.

        :param username: The username to grab from the database. Defaults to the test username.
        :type username: string

        :returns: The user object retrieved from the database.
        :rtype: login_system.models.User
        """
        return models.User.query.filter_by(username=username).first()


class Login_System(TestBase):
    """Test class for items in the base login_system module."""

    def test_unauthenticated_protected_view_redirect(self):
        """Test for trying to access an authorized protected page without being logged in."""

        response = self.app.get("/dashboard", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please log in to access this page.", response.data)
        return


class Login_System_Blueprints_Auth_Routes(TestBase):
    """Test class for items in the login_system.blueprints.auth.routes module."""

    def test_register_get(self):
        """Tests for the register endpoint for a GET request.

        login_system.blueprints.auth.register
        """

        response = self.app.get("/auth/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create an Account", response.data)
        self.assertIn(b"Already have an account?", response.data)
        return

    def test_register_post_valid(self):
        """Tests for the register endpoint for a valid POST request.

        login_system.blueprints.auth.register
        """
        request_data = dict(
            username=TEST_USERNAME,
            email=TEST_EMAIL,
            password=TEST_PASSWORD,
            confirm=TEST_PASSWORD
        )
        response = self.app.post("/auth/register", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration was successful", response.data)
        db_user = self.get_test_user()
        self.assertIsNotNone(db_user)
        self.assertEqual(db_user.username, TEST_USERNAME)
        self.assertEqual(db_user.email, TEST_EMAIL)
        self.assertNotEqual(db_user.password, "password")  # The plaintext password should NOT be in the database
        self.assertTrue(werkzeug.security.check_password_hash(db_user.password, TEST_PASSWORD))
        return

    def test_register_post_taken_creds(self):
        """Tests for the register endpoint for a POST request with provided credentials taken.

        login_system.blueprints.auth.routes.register
        """

        request_data = dict(
            username=TEST_USERNAME,
            email=TEST_EMAIL,
            password=TEST_PASSWORD,
            confirm=TEST_PASSWORD
        )
        self.add_test_user()
        response = self.app.post("/auth/register", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"That email address is already registered.", response.data)
        self.assertIn(b"That username is taken.", response.data)
        return

    def test_register_post_invalid_confirm(self):
        """Tests for the register endpoint for a POST request with invalid confirmed password.

        login_system.blueprints.auth.routes.register
        """
        request_data = dict(
            username=TEST_USERNAME,
            email=TEST_EMAIL,
            password=TEST_PASSWORD,
            confirm="invalid"
        )
        response = self.app.post("/auth/register", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Field must be equal to password", response.data)
        return

    def test_login_get(self):
        """Tests for the login endpoint for a GET request.

        login_system.blueprints.auth.routes.login
        """

        response = self.app.get("/auth/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Sign Into Your Account", response.data)
        self.assertIn(b"Don't have an account?", response.data)
        return

    def test_login_post_valid(self):
        """Tests for the login endpoint for a valid POST request.

        login_system.blueprints.auth.routes.login
        """

        self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            remember_me=False
        )
        response = self.app.post("/auth/login", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log in Successful", response.data)
        return

    def test_login_post_invalid(self):
        """Tests for the login endpoint for a POST request with an invalid password.

        login_system.blueprints.auth.routes.login
        """

        self.add_test_user()
        request_data = dict(  # nosec
            username=TEST_USERNAME,
            password="wrongpassword",
            remember_me=False
        )
        response = self.app.post("/auth/login", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid username or password", response.data)
        return

    def test_login_post_authenticated_redirect(self):
        """Tests for the login endpoint for a POST request for a user that is already authenticated.

        login_system.blueprints.auth.routes.login
        """

        self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            remember_me=True
        )
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.post("/auth/login", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"You have been logged in.", response.data)
        return

    def test_login_post_disabled_user(self):
        """Tests for the login endpoint for a POST request with a disabled user.

        login_system.blueprints.auth.routes.login
        """

        self.add_test_user(enabled=False)
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            remember_me=True
        )
        response = self.app.post("/auth/login", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your account is disabled", response.data)
        return

    def test_logout_get(self):
        """Tests for the logout endpoint.

        login_system.blueprints.auth.routes.login
        """
        self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            remember_me=True
        )
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get("/auth/logout")
        self.assertEqual(response.status_code, 302)
        self.assertIn(b'You should be redirected automatically to the target URL: <a href="/">/</a>', response.data)
        return

    def test_forgot_password_get(self):
        """Tests for the forgot password endpoint for a GET request

        login_system.blueprints.auth.routes.forgot_password
        """

        response = self.app.get("/auth/forgot_password")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Request Password Reset", response.data)
        return

    @patch("smtplib.SMTP_SSL")
    def test_forgot_password_post_valid_user(self, mock_smtplib_ssl):
        """Tests for the forgot password endpoint for a POST request with a valid user.

        login_system.blueprints.auth.routes.forgot_password
        """

        self.add_test_user()
        request_data = dict(
            identifier=TEST_USERNAME
        )
        response = self.app.post("/auth/forgot_password", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Password reset link will be sent to your email if we have one on record.", response.data)
        return

    def test_forgot_password_post_invalid_user(self):
        """Tests for the forgot password endpoint for a POST request with an invalid user.

        login_system.blueprints.auth.routes.forgot_password
        """

        request_data = dict(
            identifier="invalid"
        )
        response = self.app.post("/auth/forgot_password", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Password reset link will be sent to your email if we have one on record.", response.data)
        return

    def test_forgot_password_post_authenticated_user(self):
        """Tests for the forgot password endpoint for a POST request with an already authenticated user.

        login_system.blueprints.auth.routes.forgot_password
        """

        self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get("/auth/forgot_password", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        return

    @patch('login_system.blueprints.auth.utils.send_reset_email', **{'side_effect': RuntimeError()})
    def test_forgot_password_post_runtime_error(self, mock_send_reset_email):
        """Tests for the forgot password endpoint for a POST request that raises a runtime error.

        login_system.blueprints.auth.routes.forgot_password
        """

        self.add_test_user()
        request_data = dict(
            identifier=TEST_USERNAME
        )
        response = self.app.post("/auth/forgot_password", data=request_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"An error occurred trying to send the email. Please try again later.", response.data)

    def test_reset_password_get_token_valid(self):
        """Tests for the reset password endpoint for a GET request with a valid token.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user()
        token_data = {"user_id": user.id, "request": "password_reset"}
        reset_password_token = create_token(token_data)
        response = self.app.get(f"/auth/reset_password/{reset_password_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Password Reset", response.data)
        return

    def test_reset_password_get_token_invalid(self):
        """Tests for the reset password endpoint for a GET request with an invalid token.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user()
        token_data = {"user_id": user.id, "request": "password_reset"}
        reset_password_token = create_token(token_data, expires_sec=-100)
        response = self.app.get(f"/auth/reset_password/{reset_password_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid or Expired reset token.", response.data)
        return

    def test_reset_password_get_token_disabled_user(self):
        """Tests for the reset password endpoint for a GET request with a disabled user.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user(enabled=False)
        token_data = {"user_id": user.id, "request": "password_reset"}
        reset_password_token = create_token(token_data)
        response = self.app.get(f"/auth/reset_password/{reset_password_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your account is disabled.", response.data)
        return

    def test_reset_password_get_token_invalid_user(self):
        """Tests for the reset password endpoint for a GET request with an invalid user.

        login_system.blueprints.auth.routes.reset_password
        """

        self.add_test_user(enabled=False)
        token_data = {"user_id": "0", "request": "password_reset"}
        reset_password_token = create_token(token_data)
        response = self.app.get(f"/auth/reset_password/{reset_password_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid or Expired reset token.", response.data)
        return

    def test_reset_password_get_token_invalid_request(self):
        """Tests for the reset password endpoint for a GET request with an invalid request.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user()
        token_data = {"user_id": user.id, "request": "invalid"}
        reset_password_token = create_token(token_data)
        response = self.app.get(f"/auth/reset_password/{reset_password_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid or Expired reset token.", response.data)
        return

    def test_reset_password_get_authenticated_user(self):
        """Tests for the reset password endpoint for a GET request with an already authenticated user.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        reset_password_token = create_token({"user_id": user.id})
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get(f"/auth/reset_password/{reset_password_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"You have been logged in.", response.data)
        return

    def test_reset_password_get_token_missing_data(self):
        """Tests for the reset password endpoint for a GET request with a token missing data.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user()
        reset_password_token = create_token({"user_id": user.id})
        response = self.app.get(f"/auth/reset_password/{reset_password_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid reset token.", response.data)
        self.assertIn(b"Request Password Reset", response.data)
        return

    def test_reset_password_post_valid(self):
        """Tests for the reset password endpoint for a POST request with a valid password.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user()
        request_data = dict(  # nosec
            password="Newp@ssw0rd",
            confirm="Newp@ssw0rd"
        )
        token_data = {"user_id": user.id, "request": "password_reset"}
        reset_password_token = create_token(token_data)
        response = self.app.post(f"/auth/reset_password/{reset_password_token}", data=request_data, follow_redirects=True)
        user = self.get_test_user()

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your password has been updated.", response.data)
        self.assertIn(b"Sign Into Your Account", response.data)
        self.assertNotEqual(user.password, "newpassword")  # The password itself should not be in the db
        self.assertFalse(werkzeug.security.check_password_hash(user.password, "password"))
        self.assertTrue(werkzeug.security.check_password_hash(user.password, "Newp@ssw0rd"))
        return

    def test_reset_password_post_key_error(self):
        """Tests for the reset password endpoint for a POST request with an invalid request error.

        login_system.blueprints.auth.routes.reset_password
        """

        user = self.add_test_user()
        request_data = dict(  # nosec
            password="Newp@ssw0rd",
            confirm="Newp@ssw0rd"
        )
        token_data = {"user_id": user.id, "request": "invalid"}
        reset_password_token = create_token(token_data)
        response = self.app.post(f"/auth/reset_password/{reset_password_token}", data=request_data, follow_redirects=True)
        user = self.get_test_user()

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid or Expired reset token.", response.data)
        self.assertNotEqual(user.password, "newpassword")  # The password itself should not be in the db
        self.assertTrue(werkzeug.security.check_password_hash(user.password, TEST_PASSWORD))
        self.assertFalse(werkzeug.security.check_password_hash(user.password, "Newp@ssw0rd"))
        return

    @patch("smtplib.SMTP_SSL")
    def test_confirm_email_request(self, mock_smtp_ssl):
        """Tests for the confirm_email_request endpoint for a GET request.

        login_system.blueprints.auth.routes.confirm_email_request
        """

        self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get("/auth/confirm_email_request", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Confirmation email sent.", response.data)
        return

    def test_confirm_email_request_already_validated(self):
        """Tests for the confirm_email_request endpoint for a GET request with an email address that
            is already validated.

        login_system.blueprints.auth.routes.confirm_email_request
        """

        self.add_test_user(email_validated=True)
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get("/auth/confirm_email_request", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your email address is already confirmed.", response.data)
        return

    @patch("login_system.blueprints.auth.utils.send_email_confirmation", **{'side_effect': RuntimeError()})
    def test_confirm_email_request_runtime_error(self, mock_send_email_confirmation):
        """Tests for the confirm_email_request endpoint for a GET request that results in a runtime error.

        login_system.blueprints.auth.routes.confirm_email_request
        """

        self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get("/auth/confirm_email_request", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"An error occurred trying to send the email. Please try again later.", response.data)
        return

    def test_confirm_email_valid_token(self):
        """Tests for the confirm_email endpoint for a GET request with a valid token.

        login_system.blueprints.auth.routes.confirm_email
        """

        user = self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        token_data = {"user_id": user.id, "email": user.email, "request": "email_confirmation"}
        confirm_email_token = create_token(token_data)
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get(f"/auth/confirm_email/{confirm_email_token}", follow_redirects=True)
        user = self.get_test_user()
        self.assertTrue(user.email_validated)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your email address has been confirmed.", response.data)
        return

    def test_confirm_email_invalid_token(self):
        """Tests for the confirm_email endpoint for a GET request with an expired token.

        login_system.blueprints.auth.routes.confirm_email
        """

        user = self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        token_data = {"user_id": user.id, "email": user.email, "request": "email_confirmation"}
        confirm_email_token = create_token(token_data, expires_sec=-100)
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get(f"/auth/confirm_email/{confirm_email_token}", follow_redirects=True)
        user = self.get_test_user()
        self.assertFalse(user.email_validated)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid or Expired confirmation token.", response.data)
        return

    def test_confirm_email_invalid_user_id(self):
        """Tests for the confirm_email endpoint for a GET request with an invalid user id.

        login_system.blueprints.auth.routes.confirm_email
        """

        user = self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        token_data = {"user_id": 1, "email": user.email, "request": "email_confirmation"}
        confirm_email_token = create_token(token_data)
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get(f"/auth/confirm_email/{confirm_email_token}", follow_redirects=True)
        user = self.get_test_user()
        self.assertFalse(user.email_validated)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid confirmation token.", response.data)
        return

    def test_confirm_email_invalid_email(self):
        """Tests for the confirm_email endpoint for a GET request with an invalid email address.

        login_system.blueprints.auth.routes.confirm_email
        """

        user = self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        token_data = {"user_id": user.id, "email": "not@user.email", "request": "email_confirmation"}
        confirm_email_token = create_token(token_data)
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get(f"/auth/confirm_email/{confirm_email_token}", follow_redirects=True)
        user = self.get_test_user()
        self.assertFalse(user.email_validated)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid confirmation token.", response.data)
        return

    def test_confirm_email_invalid_request(self):
        """Tests for the confirm_email endpoint for a GET request with an invalid request.

        login_system.blueprints.auth.routes.confirm_email
        """

        user = self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        token_data = {"user_id": user.id, "email": user.email, "request": "invalid"}
        confirm_email_token = create_token(token_data)
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get(f"/auth/confirm_email/{confirm_email_token}", follow_redirects=True)
        user = self.get_test_user()
        self.assertFalse(user.email_validated)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid confirmation token.", response.data)
        return

    def test_confirm_email_key_error(self):
        """Tests for the confirm_email endpoint for a GET request with a token not containing the proper data.

        login_system.blueprints.auth.routes.confirm_email
        """

        user = self.add_test_user()
        request_data = dict(
            username=TEST_USERNAME,
            password=TEST_PASSWORD
        )
        token_data = {"user_id": user.id, "email": user.email}
        confirm_email_token = create_token(token_data)
        with self.app:
            self.app.post("/auth/login", data=request_data, follow_redirects=True)
            response = self.app.get(f"/auth/confirm_email/{confirm_email_token}", follow_redirects=True)
        user = self.get_test_user()
        self.assertFalse(user.email_validated)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid Confirmation Token.", response.data)
        return

    def test_report_email_confirmation_valid(self):
        """Tests for the report_email_confirmation endpoint for a GET request with a valid token.

        login_system.blueprints.auth.routes.report_email_confirmation
        """

        user = self.add_test_user()
        email_report_token = create_token({"user_id": user.id, "email": user.email, "request": "report_email"})
        response = self.app.get(f"/auth/report_confirmation/{email_report_token}", follow_redirects=True)
        user = self.get_test_user()
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"The account associated with {user.email} has been disabled.".encode("utf8"), response.data)
        self.assertFalse(user.enabled)
        return

    def test_report_email_confirmation_invalid_token(self):
        """Tests for the report_email_confirmation endpoint for a GET request with an invalid token.

        login_system.blueprints.auth.routes.report_email_confirmation
        """

        user = self.add_test_user()
        email_report_token = create_token({"user_id": user.id, "email": user.email, "request": "report_email"}, expires_sec=-100)
        response = self.app.get(f"/auth/report_confirmation/{email_report_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid or Expired token", response.data)
        user = self.get_test_user()
        self.assertTrue(user.enabled)
        return

    def test_report_email_confirmation_invalid_request(self):
        """Tests for the report_email_confirmation endpoint for a GET request with a invalid request data.

        login_system.blueprints.auth.routes.report_email_confirmation
        """

        user = self.add_test_user()
        email_report_token = create_token({"user_id": user.id, "email": user.email, "request": "invalid"})
        response = self.app.get(f"/auth/report_confirmation/{email_report_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid token. Token not for reporting emails.", response.data)
        user = self.get_test_user()
        self.assertTrue(user.enabled)
        return

    def test_report_email_confirmation_invalid_email(self):
        """Tests for the report_email_confirmation endpoint for a GET request with an invalid email.

        login_system.blueprints.auth.routes.report_email_confirmation
        """

        user = self.add_test_user()
        email_report_token = create_token({"user_id": user.id, "email": "not@user.com", "request": "report_email"})
        response = self.app.get(f"/auth/report_confirmation/{email_report_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid token. Email does not match user.", response.data)
        user = self.get_test_user()
        self.assertTrue(user.enabled)
        return

    def test_report_email_confirmation_invalid_user_id(self):
        """Tests for the report_email_confirmation endpoint for a GET request with an invalid user id.

        login_system.blueprints.auth.routes.report_email_confirmation
        """

        user = self.add_test_user()
        email_report_token = create_token({"user_id": "0", "email": user.email, "request": "report_email"})
        response = self.app.get(f"/auth/report_confirmation/{email_report_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid token. This user does not exist.", response.data)
        user = self.get_test_user()
        self.assertTrue(user.enabled)
        return

    def test_report_email_confirmation_key_error(self):
        """Tests for the report_email_confirmation endpoint for a GET request with a token not containing required data.

        login_system.blueprints.auth.routes.report_email_confirmation
        """

        user = self.add_test_user()
        email_report_token = create_token({"user_id": user.id, "email": user.email})
        response = self.app.get(f"/auth/report_confirmation/{email_report_token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid Report Token.", response.data)
        user = self.get_test_user()
        self.assertTrue(user.enabled)
        return


class Login_System_Blueprints_Auth_Utils(TestBase):
    """Test class for items in the login_system.blueprints.auth.utils module."""

    @patch("smtplib.SMTP_SSL", **{"side_effect": RuntimeError()})
    def test_send_reset_email_runtime_error(self, mock_smtp_ssl):
        """Tests for the reset email builder that raises a runtime error.

        login_system.blueprints.auth.utils.send_reset_email
        """

        user = self.add_test_user()
        with app.app_context():
            with self.assertRaises(RuntimeError):
                login_system.blueprints.auth.utils.send_reset_email(user)
        return

    @patch("smtplib.SMTP_SSL", **{"side_effect": RuntimeError()})
    def test_send_email_confirmation_runtime_error(self, mock_smtp_ssl):
        """Tests for the email confirmation builder that raises a runtime error.

        login_system.blueprints.auth.utils.send_email_confirmation
        """

        user = self.add_test_user()
        with app.app_context():
            with self.assertRaises(RuntimeError):
                login_system.blueprints.auth.utils.send_email_confirmation(user)
        return


class Login_System_Blueprints_Auth_Forms(TestBase):
    """Test class for items in the login_system.blueprints.auth.forms module."""

    def test_lowercase_pw_character_check_valid(self):
        """Tests for the lowercase character form validator with a valid input.

        login_system.blueprints.auth.forms.lowercase_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "password"
            ret = login_system.blueprints.auth.forms.lowercase_pw_character_check(form, test_pw)
        self.assertIsNone(ret)

    def test_lowercase_pw_character_check_invalid(self):
        """Tests for the lowercase character form validator with an invalid input.

        login_system.blueprints.auth.forms.lowercase_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "PASSWORD"
            with self.assertRaises(wtforms.validators.ValidationError):
                login_system.blueprints.auth.forms.lowercase_pw_character_check(form, test_pw)

    def test_uppercase_pw_character_check_valid(self):
        """Tests for the uppercase character form validator with a valid input.

        login_system.blueprints.auth.forms.uppercase_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "PASSWORD"
            ret = login_system.blueprints.auth.forms.uppercase_pw_character_check(form, test_pw)
        self.assertIsNone(ret)

    def test_uppercase_pw_character_check_invalid(self):
        """Tests for the uppercase character form validator with an invalid input.

        login_system.blueprints.auth.forms.uppercase_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "password"
            with self.assertRaises(wtforms.validators.ValidationError):
                login_system.blueprints.auth.forms.uppercase_pw_character_check(form, test_pw)

    def test_digits_pw_character_check_valid(self):
        """Tests for the digit form validator with a valid input.

        login_system.blueprints.auth.forms.digits_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "password123"
            ret = login_system.blueprints.auth.forms.digits_pw_character_check(form, test_pw)
        self.assertIsNone(ret)

    def test_digits_pw_character_check_invalid(self):
        """Tests for the digit form validator with an invalid input.

        login_system.blueprints.auth.forms.digits_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "password"
            with self.assertRaises(wtforms.validators.ValidationError):
                login_system.blueprints.auth.forms.digits_pw_character_check(form, test_pw)

    def test_special_characters_pw_character_check_valid(self):
        """Tests for the special character form validator with a valid input.

        login_system.blueprints.auth.forms.special_characters_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "password@"
            ret = login_system.blueprints.auth.forms.special_characters_pw_character_check(form, test_pw)
        self.assertIsNone(ret)

    def test_special_characters_pw_character_check_invalid(self):
        """Tests for the special character form validator with an invalid input.

        login_system.blueprints.auth.forms.special_characters_pw_character_check
        """

        with app.app_context():
            form = login_system.blueprints.auth.forms.RegisterForm()
            test_pw = wtforms.fields.PasswordField()
            test_pw.data = "password"
            with self.assertRaises(wtforms.validators.ValidationError):
                login_system.blueprints.auth.forms.special_characters_pw_character_check(form, test_pw)


if __name__ == '__main__':
    unittest.main()
