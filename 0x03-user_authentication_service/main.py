#!/usr/bin/env python3
"""Main file
"""
import requests


def register_user(email: str, password: str) -> None:
    """Test user regestration
    """
    url = f"{BASE_URL}/users"
    payload = {'email': email, 'password': password}

    res = requests.post(url, data=payload)
    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "user created"}
    res = requests.post(url, data=payload)
    assert res.status_code == 400
    assert res.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """
    """
    pass


def log_in(email: str, password: str) -> str:
    """
    """
    pass


def profile_unlogged() -> None:
    """
    """
    pass


def profile_logged(session_id: str) -> None:
    """
    """
    pass


def log_out(session_id: str) -> None:
    """
    """
    pass


def reset_password_token(email: str) -> str:
    """
    """
    pass


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """
    """
    pass


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
