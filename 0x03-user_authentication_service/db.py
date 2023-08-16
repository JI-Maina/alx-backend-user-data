#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User

VALID_FIELDS = ['id', 'email', 'hashed_password', 'session_id', 'reset_token']


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str):
        """Saves the user to the database and returns the saved User object
        """
        if email and hashed_password:
            user = User(email=email, hashed_password=hashed_password)
            session = self._session
            session.add(user)
            session.commit()
            return user

    def find_user_by(self, **kwargs) -> User:
        """takes in arbitrary keyword arguments and returns the first row found
        in the users"""

        if not kwargs or any(key not in VALID_FIELDS for key in kwargs):
            raise InvalidRequestError
        session = self._session
        try:
            return session.query(User).filter(**kwargs).one()
        except Exception:
            raise NoResultFound
