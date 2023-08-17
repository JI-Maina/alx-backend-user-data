#!/usr/bin/env python3
"""Defines a _hash_password method that takes in a password string arguments
"""
import bcrypt

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """takes in a password string arguments and returns bytes
    """

    salt = bcrypt.gensalt()
    byts = password.encode('utf-8')
    hashed_pwd = bcrypt.hashpw(byts, salt)

    return hashed_pwd


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """initializes the authentication db"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """registers user in the database
        """
        db = self._db._session
        old_user = db.query(User).filter_by(email=email).first()

        if old_user:
            raise ValueError(f'{email} already exists')

        hashed_pwd = _hash_password(password)

        user = User(email=email, hashed_password=hashed_pwd)
        db.add(user)
        db.commit()

        return user
