#!/usr/bin/env python3
"""Defines a _hash_password method that takes in a password string arguments
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """takes in a password string arguments and returns bytes
    """

    salt = bcrypt.gensalt()
    byts = password.encode('utf-8')
    hashed_pwd = bcrypt.hashpw(byts, salt)

    return hashed_pwd
