#!/usr/bin/env python3
from flask import Blueprint, render_template

public = Blueprint("public", __name__)


@public.route("/", methods=["GET"])
def index():
    """Route to handle the index page."""

    return render_template("index.html", show_account_buttons=True)
