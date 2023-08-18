#!/usr/bin/env python3
"""Sets a basic Flask app
"""
from flask import Flask, jsonify, request, abort, redirect

from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route('/', strict_slashes=False)
def index():
    """GET /
    Return:
      - JSON payload
    """

    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """POST /users registers a user
    Return:
      - a payload with relevant msg either on success or error
    """
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": f'{email}', "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """POST /sessions
    Return:
      - 401 HTTP status If the login information is incorrect
      - otherwise success message
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)

    response = jsonify({"email": f"{email}", "message": "logged in"})
    response.set_cookie("session_id", session_id)

    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """DELETE /sessions
    Return:
      - If the user exists destroy the session and redirect the user to GET /
      - If the user does not exist, respond with a 403 HTTP status
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        AUTH.destroy_session(user.id)
        return redirect('/'), 302

    abort(403)


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile():
    """GET /profile
    Return:
      - If the user exist, respond with a 200 HTTP status
      - If session ID is invalid or no user, respond with a 403 HTTP status
    """
    session_id = request.cookies.get("session_id")

    if session_id:
        user = AUTH.get_user_from_session_id(session_id)

        if user:
            return jsonify({"email": f"{user.email}"}), 200

    abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """POST /reset_password
    Return:
      - If the email is not registered, respond with a 403 status code
      - Otherwise, generate a token and respond with a 200 HTTP status
    """
    email = request.form.get('email')

    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": f"{email}", "reset_token": f"{token}"})
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password():
    """PUT /reset_password, Update the password
    Return:
     - If token is invalid, catch the exception and respond with 403 HTTP code
     - Otherwise, respond with a 200 HTTP code
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        AUTH.update_password(reset_token, password)
        return jsonify({"email": f"{email}", "message": "Password updated"})
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000", debug=True)
