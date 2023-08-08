#!/usr/bin/env python3
"""Defines basic_auth authentication class
"""
from api.v1.auth.auth import Auth
from base64 import b64decode
import binascii


class BasicAuth(Auth):
    """Deines Basic_authentication requirements
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header for a
        Basic Authentication"""

        if authorization_header:
            if isinstance(authorization_header, str):
                if authorization_header.startswith("Basic "):
                    return authorization_header[6:]
                return None
            return None
        return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64 string
        base64_authorization_header"""

        if base64_authorization_header:
            if isinstance(base64_authorization_header, str):
                try:
                    x = b64decode(base64_authorization_header)
                except (binascii.Error, UnicodeDecodeError):
                    return None
                return x.decode('utf-8')
            return None
        return None
