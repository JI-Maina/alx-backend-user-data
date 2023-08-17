#!/usr/bin/env python3
"""Defines a _hash_password method that takes in a password string arguments
"""
import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound

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

    def _generate_uuid(self) -> str:
        """return a string representation of a new UUID
        """
        return str(uuid.uuid4())

    def register_user(self, email: str, password: str) -> User:
        """registers user in the database
        """
        db = self._db

        try:
            db.find_user_by(email=email)
            raise ValueError(f'{email} already exists')
        except NoResultFound:
            hashed_pwd = _hash_password(password)
            return db.add_user(email, hashed_pwd)

    def valid_login(self, email: str, password: str) -> bool:
        """Returns true if user with that email exists and users password
        matches, otherwise false."""
        db = self._db
        try:
            user = db.find_user_by(email=email)
            byts = password.encode('utf-8')

            if bcrypt.checkpw(byts, user.hashed_password):
                return True
            return False
        except NoResultFound:
            return False
