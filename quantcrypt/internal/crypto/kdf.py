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
from enum import Enum
from zxcvbn import zxcvbn
from dotmap import DotMap
from typing import Annotated
from argon2 import PasswordHasher
from argon2 import exceptions as aex
from pydantic import ConfigDict, Field, validate_call
from abc import ABC, abstractmethod
from quantcrypt.errors import *


_validator = validate_call(config=ConfigDict(
	arbitrary_types_allowed=True
))


class KDFMemCost(Enum):
	MiB_32 = 2**15
	MiB_64 = 2**16
	MiB_128 = 2**17
	MiB_256 = 2**18
	MiB_512 = 2**19
	GiB_1 = 2**20
	GiB_2 = 2**21
	GiB_4 = 2**22
	GiB_8 = 2**23
	GiB_16 = 2**24
	GiB_32 = 2**25


class Argon2Params(DotMap):
	@validate_call
	def __init__(
			self,
			memory_cost: KDFMemCost,
			parallelism: Annotated[int, Field(gt=0)],
			time_cost: Annotated[int, Field(gt=0)],
			hash_len: Annotated[int, Field(ge=16, le=64)] = 32,
			salt_len: Annotated[int, Field(ge=16, le=64)] = 32
	):
		memory_cost = memory_cost.value
		super().__init__({
			k: v for k, v in locals().items()
			if k not in ["self", "__class__"]
		})


class BaseArgon2(ABC):
	_testing: bool = False
	_engine: PasswordHasher
	params: Argon2Params

	@staticmethod
	@abstractmethod
	def _default_params() -> Argon2Params: ...

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

	def __init__(self, overrides: Argon2Params | None):
		params = overrides or self._default_params()
		if not overrides and self._testing:
			params.memory_cost = 2**10
		self._engine = PasswordHasher(**params.toDict())
		self.params = params


class KDF:
	class Argon2(BaseArgon2):
		public_hash: str = None
		rehashed: bool = False
		verified: bool = False

		@staticmethod
		def _default_params() -> Argon2Params:
			# Using 1 GiB of memory and approx 0.5 seconds
			# on 12-th Gen Intel i7 at 2.2 GHz
			return Argon2Params(
				memory_cost=KDFMemCost.GiB_1,
				parallelism=8,
				time_cost=3,
				hash_len=32,
				salt_len=32
			)

		@_validator
		def __init__(
				self,
				password: str,
				verif_hash: str = None,
				*,
				min_years: int = 1,
				params: Argon2Params = None
		):
			if not verif_hash and min_years > 0:
				data_key = "online_no_throttling_10_per_second"
				self._assert_crack_resistance(password, min_years, data_key)

			super().__init__(params)
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

	class Argon2Key(BaseArgon2):
		secret_key: bytes = None
		public_salt: str = None

		@staticmethod
		def _default_params() -> Argon2Params:
			# Using 4 GiB of memory and approx 3.0 seconds
			# on 12-th Gen Intel i7 at 2.2 GHz
			return Argon2Params(
				memory_cost=KDFMemCost.GiB_4,
				parallelism=8,
				time_cost=5,
				hash_len=32,
				salt_len=32
			)

		@_validator
		def __init__(
				self,
				password: str,
				public_salt: str = None,
				*,
				min_years: int = 10,
				params: Argon2Params = None
		):
			if not public_salt and min_years > 0:
				data_key = "offline_slow_hashing_1e4_per_second"
				self._assert_crack_resistance(password, min_years, data_key)

			super().__init__(params)
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
