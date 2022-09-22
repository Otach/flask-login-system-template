#!/bin/bash

# General purpose script to start the flask application in it's multiple
# modes. Passing parameters to the script will allow different modes
# to be started.
#
# Parameters:
#   None:
#       This is the default passed with no arguments. The server will start in
#       production mode using a wsgi server on port 5000
#
#   "dev":
#       This is the parameter to start the server in the development mode. It
#       sets the debug flag in the flask runner and starts the server on port
#       5000 on all interfaces.
#
#   "test":
#       This is the parameter to run the tests in the tests.py file. No accessable
#       server will be started using this parameter.


# Production and Dev environments require an external database connection, so we need to
#  wait for the database to accept connections.
waitForDB () {

    # https://stackoverflow.com/questions/30888109/shell-script-to-check-if-mysql-is-up-or-down
    echo "Waiting for database to startup."
    check=""
    while [ -z "$check" ]; do
        sleep 1
        check=$(wget -O - -T 2 "http://$MYSQL_HOST:3306" 2>&1 | grep -o "200 No headers")
    done
    echo "Database Responded"

    echo "Updating Database Config"
    flask db upgrade
    echo "Migration Complete"
}


if [ $1 == "dev" ]; then
    waitForDB
    echo "Starting Development Server"
    flask --debug run --host 0.0.0.0

elif [ $1 == "test" ]; then
    echo "Running Tests"
    python tests.py

else
    waitForDB
    echo "Starting Production Server"
    gunicorn --bind 0.0.0.0:5000 -w 5 login_system_wsgi:application
fi
