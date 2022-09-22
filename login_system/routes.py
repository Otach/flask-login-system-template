#!/usr/bin/env python3
from login_system import app

import werkzeug


@app.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_requests(e):
    """Route for HTTP 400 responses."""

    return "Bad request", 400


@app.errorhandler(werkzeug.exceptions.NotFound)
def not_found(e):
    """Route for HTTP 404 responses."""

    return "Page not Found", 404


@app.errorhandler(werkzeug.exceptions.MethodNotAllowed)
def method_not_allowed(e):
    """Route for HTTP 405 responses."""

    return "Method Not Allowed", 405


@app.errorhandler(werkzeug.exceptions.Forbidden)
def forbidden(e):
    """Route for HTTP 403 responses."""

    return "Forbidden", 403
