#!/usr/bin/env python3
from flask import Blueprint, render_template
from login_system.blueprints.auth.utils import authorized

dashboard = Blueprint("dashboard", __name__)


@dashboard.route("/")
@authorized
def dashboard_index():
    return render_template("dashboard.html")
