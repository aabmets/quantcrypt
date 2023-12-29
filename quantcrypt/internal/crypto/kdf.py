#
#   MIT License
#   
#   Copyright (c) 2024, Mattias Aabmets
#   
#   The contents of this file are subject to the terms and conditions defined in the License.
#   You may not use, modify, or distribute this file except in compliance with the License.
#   
#   SPDX-License-Identifier: MIT
#
import base64
import secrets
from zxcvbn import zxcvbn
from pydantic import validate_call
from argon2 import PasswordHasher, Parameters
from argon2 import exceptions as aex
from argon2 import low_level as lvl
from quantcrypt.errors import *


class BaseArgon2:
	_engine: PasswordHasher
	parameters: Parameters

	@staticmethod
	def _assert_crack_resistance(password: str, min_years: int, data_key: str) -> None:
		result: dict = zxcvbn(password)
		data = result["crack_times_seconds"][data_key]
		real_years = int(data) // (365 * 24 * 3600)
		if real_years < min_years:
			raise KDFWeakPasswordError

	@validate_call
	def __init__(self, mc: int, tc: int, lanes: int):
		kwargs = dict(
			hash_len=32,
			salt_len=32,
			time_cost=tc,
			memory_cost=mc,
			parallelism=lanes
		)
		self._engine = PasswordHasher(**kwargs)
		self.parameters = Parameters(
			version=lvl.ARGON2_VERSION,
			type=lvl.Type.ID,
			**kwargs
		)


class KDF:
	class Argon2Web(BaseArgon2):
		public_hash: str = None
		rehashed: bool = False
		verified: bool = False

		@validate_call
		def __init__(
				self, password: str, verif_hash: str = None,
				*, min_years: int = 1, testing: bool = False
		):
			if min_years > 0:
				data_key = "online_no_throttling_10_per_second"
				self._assert_crack_resistance(password, min_years, data_key)

			# Using 512 MB of memory and 0.5 seconds on 12-th Gen Intel i7 at 2.2 GHz
			super().__init__(mc=2 ** (10 if testing else 19), tc=6, lanes=8)
			try:
				if verif_hash is None:
					self.public_hash = self._engine.hash(password)
				else:
					self._engine.verify(verif_hash, password)
					if self._engine.check_needs_rehash(verif_hash):
						self.public_hash = self._engine.hash(password)
						self.rehashed = True
					self.public_hash = verif_hash
					self.verified = True
			except aex.VerificationError:
				raise KDFVerificationError
			except aex.InvalidHashError:
				raise KDFInvalidHashError
			except aex.HashingError:
				raise KDFHashingError

	class Argon2File(BaseArgon2):
		secret_hash: bytes = None
		public_salt: str = None

		@validate_call
		def __init__(
				self, password: str, public_salt: str = None,
				*, min_years: int = 10, testing: bool = False
		):
			if min_years > 0:
				data_key = "offline_slow_hashing_1e4_per_second"
				self._assert_crack_resistance(password, min_years, data_key)

			# Using 4 GB of memory and 3.3 seconds on 12-th Gen Intel i7 at 2.2 GHz
			super().__init__(mc=2 ** (10 if testing else 22), tc=4, lanes=8)

			try:
				salt_bytes = (
					secrets.token_bytes(32)
					if public_salt is None else
					base64.b64decode(public_salt.encode())
				)
				secret_hash = self._engine.hash(
					password, salt=salt_bytes
				)
				_salt, _hash = secret_hash.split('$')[-2:]
				self.public_salt = f"{_salt}="
				self.secret_hash = base64.b64decode(
					f"{_hash}=".encode()
				)
			except aex.HashingError:
				raise KDFHashingError
