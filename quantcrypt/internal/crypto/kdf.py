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
from __future__ import annotations
import base64
import secrets
from pydantic import (
	model_validator,
	validate_call,
	BaseModel
)
from zxcvbn import zxcvbn
from argon2 import PasswordHasher
from argon2 import exceptions as aex
from abc import ABC, abstractmethod
from quantcrypt.errors import *


class Argon2Params(BaseModel):
	parallelism: int
	memory_cost: int
	time_cost: int
	hash_len: int
	salt_len: int

	def __init__(
			self,
			parallelism: int,
			memory_cost: int,
			time_cost: int,
			hash_len: int,
			salt_len: int
	):
		"""Custom parameters for KDF Argon2 classes."""
		kwargs = locals()
		kwargs.pop('self')
		super().__init__(**kwargs)

	@model_validator(mode='after')
	def validate_model(self) -> Argon2Params:
		assert self.parallelism >= 1, \
			"Parallelism cannot be 0 or negative."
		assert self.memory_cost >= 1024, \
			"Memory cost must be greater than or equal to 2**10 (1 MB)."
		assert self.memory_cost <= 33554432, \
			"Memory cost must be less than or equal to 2**25 (32 GB)."
		assert (self.memory_cost & (self.memory_cost - 1)) == 0, \
			"Memory cost value must be a power of 2."
		assert self.time_cost >= 1, \
			"Time cost cannot be 0 or negative."
		assert self.hash_len >= 32, \
			"Hash length must be at least 32."
		assert self.salt_len >= 32, \
			"Salt length must be at least 32."
		return self


class BaseArgon2(ABC):
	_engine: PasswordHasher
	params: Argon2Params

	@staticmethod
	@abstractmethod
	def _default_params(testing: bool) -> Argon2Params: ...

	@staticmethod
	def _assert_crack_resistance(password: str, min_years: int, data_key: str) -> None:
		result: dict = zxcvbn(password)
		data = result["crack_times_seconds"][data_key]
		real_years = int(data) // (365 * 24 * 3600)
		if real_years < min_years:
			raise KDFWeakPasswordError

	@staticmethod
	def _pad_b64_str(data: str) -> str:
		if remainder := len(data) % 4:
			return data + '=' * (4 - remainder)
		return data

	def __init__(self, overrides: Argon2Params, testing: bool):
		params = overrides or self._default_params(testing)
		self._engine = PasswordHasher(**params.model_dump())
		self.params = params


class KDF:
	class Argon2Hash(BaseArgon2):
		public_hash: str = None
		rehashed: bool = False
		verified: bool = False

		@staticmethod
		def _default_params(testing) -> Argon2Params:
			# Using 512 MB of memory and 0.5 seconds
			# on 12-th Gen Intel i7 at 2.2 GHz
			return Argon2Params(
				memory_cost=2**(10 if testing else 19),
				parallelism=8,
				time_cost=6,
				hash_len=32,
				salt_len=32
			)

		@validate_call
		def __init__(
				self,
				password: str,
				verif_hash: str = None,
				*,
				min_years: int = 1,
				testing: bool = False,
				params: Argon2Params = None
		):
			if not verif_hash and min_years > 0:
				data_key = "online_no_throttling_10_per_second"
				self._assert_crack_resistance(password, min_years, data_key)

			super().__init__(params, testing)
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

	class Argon2Secret(BaseArgon2):
		secret_key: bytes = None
		public_salt: str = None

		@staticmethod
		def _default_params(testing) -> Argon2Params:
			# Using 4 GB of memory and 3.3 seconds
			# on 12-th Gen Intel i7 at 2.2 GHz
			return Argon2Params(
				memory_cost=2**(10 if testing else 22),
				parallelism=8,
				time_cost=4,
				hash_len=32,
				salt_len=32
			)

		@validate_call
		def __init__(
				self,
				password: str,
				public_salt: str = None,
				*,
				min_years: int = 10,
				testing: bool = False,
				params: Argon2Params = None
		):
			if not public_salt and min_years > 0:
				data_key = "offline_slow_hashing_1e4_per_second"
				self._assert_crack_resistance(password, min_years, data_key)

			super().__init__(params, testing)
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
				self.secret_key = base64.b64decode(
					self._pad_b64_str(_hash).encode()
				)
			except aex.HashingError:
				raise KDFHashingError
