#!/usr/bin/env python3
"""Defines a class to manage the API authentication
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Manages API authentication
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """returns False - path and excluded_paths
        """
        check = path
        if path is None or excluded_paths is None or len(excluded_paths) < 1:
            return True
        if path[-1] != "/":
            check += "/"
        if check in excluded_paths or path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """returns None - requestreturns None - request
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """returns None - request
        """
        return None
