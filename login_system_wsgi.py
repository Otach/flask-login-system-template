#!/usr/bin/python3
import logging
import sys

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, "/login_system")
from login_system import app as application  # noqa
