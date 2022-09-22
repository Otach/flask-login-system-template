# Flask Login System Template

---

**NOTE:** This is *NOT* a flask extension. This is a flask application with a login system implementation. It is useful as a template to start developing a flask application that uses a login system without having to rewrite the code each time.

---

## Why?
This is mainly a way to prevent rebuilding a login system each time I create a new flask application.
I am hosting it here hoping it may be useful for someone looking to build a login system but have no idea where to start
or just want to use a prebuilt login system.

## Layout
The main source for the application is in the `login_system` folder. Mostly everything above this directory are helpers
that allow the application to run correctly.

`login_system.__init__`:

 - Setup of the flask application
    - Configuration Loading
    - Flask Extensions Initialization
    - Blueprint registering

`login_system.routes`:

 - HTTP Error Handling routes

`login_system.models`:

 - User database model class
 - Flask-Login user loader

`login_system.config`:

 - Flask Configuration Variables for the login system

`login_system.blueprints.auth`:

 - The routes, forms and utils for the authentication blueprint

`login_system.blueprints.dashboard`:

 - The routes for the application areas behind the login system

`login_system.blueprints.public`:

 - The routes for the application areas that can be access without logging in

`login_system.templates`:

 - The templates and bases used in the application

`login_system.static`:

 - The static files (css, js, etc.) used in the application


## Running
This flask application is designed to run in docker containers as that is my preferred way of developing and deploying flask applications.

To start the development server:

```sh
cd docker-compose
docker-compose -f docker-compose.dev.yml up --build
```
Access the server by navigating to http://localhost:12000

To run the tests for the login system:
```sh
cd docker-compose
docker-compose -f docker-compose.test.yml up --build
```
