from flask import Flask, request
from .auth import Auth
from typing import TypeVar
from models.user import User

#!/usr/bin/env python3
"""Basic Auth Implementation"""


class BasicAuth:
	"""BasicAuth class"""

	def extract_base64_authorization_header(self, authorization_header: str) -> str:
		"""Extracts base64 authorization header"""
		if authorization_header is None or not isinstance(authorization_header, str):
			return None
		if not authorization_header.startswith("Basic "):
			return None
		else:
			return authorization_header[6:]

	def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
		"""Decodes base64 authorization header"""
		if base64_authorization_header is None or not isinstance(base64_authorization_header, str):
			return None
		try:
			return base64_authorization_header.decode('utf-8')
		except Exception:
			return None

	def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
		"""Extracts user credentials"""
		if decoded_base64_authorization_header is None or not isinstance(decoded_base64_authorization_header, str):
			return (None, None)
		if ':' not in decoded_base64_authorization_header:
			return (None, None)
		credentials = decoded_base64_authorization_header.split(':', 1)
		return (credentials[0], credentials[1])

	def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
		"""User object from credentials"""
		if user_email is None or not isinstance(user_email, str):
			return None
		if user_pwd is None or not isinstance(user_pwd, str):
			return None
		user = User.search({'email': user_email})
		if user is None or not user.is_valid_password(user_pwd):
			return None
		return user

	def current_user(self, request=None) -> TypeVar('User'):
		"""Current user"""
		auth_header = self.authorization_header(request)
		base64_header = self.extract_base64_authorization_header(auth_header)
		decoded_header = self.decode_base64_authorization_header(base64_header)
		credentials = self.extract_user_credentials(decoded_header)
		return self.user_object_from_credentials(credentials[0], credentials[1])
