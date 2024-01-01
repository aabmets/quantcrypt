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
from pydantic import Field, validate_call
from abc import ABC, abstractmethod
from quantcrypt.errors import *
from .common import InputValidator


class KDFMemCost(Enum):
	"""
	The amount of memory in MiB or GiB
	a key derivation function must use.
	"""
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


class KDFParams(DotMap):
	@validate_call
	def __init__(
			self,
			memory_cost: KDFMemCost,
			parallelism: Annotated[int, Field(gt=0)],
			time_cost: Annotated[int, Field(gt=0)],
			hash_len: Annotated[int, Field(ge=16, le=64)] = 32,
			salt_len: Annotated[int, Field(ge=16, le=64)] = 32
	):
		"""
		Custom parameters for altering the security
		level of key derivation functions.

		:param memory_cost: The amount of memory the KDF must use.
		:param parallelism: Up to how many threads the KDF can use.
		:param time_cost: The amount of iterations the KDF must run.
		:param hash_len: The length of the generated hash, in bytes.
		:param salt_len: The length of the generated salt, in bytes.
		"""
		memory_cost = memory_cost.value
		super().__init__({
			k: v for k, v in locals().items()
			if k not in ["self", "__class__"]
		})


class BaseArgon2(ABC):
	_testing: bool = False
	_engine: PasswordHasher
	params: KDFParams

	@staticmethod
	@abstractmethod
	def _default_params() -> KDFParams: ...

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

	def __init__(self, overrides: KDFParams | None):
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
		def _default_params() -> KDFParams:
			return KDFParams(
				memory_cost=KDFMemCost.GiB_1,
				parallelism=8,
				time_cost=3,
				hash_len=32,
				salt_len=32
			)

		@InputValidator()
		def __init__(
				self,
				password: str,
				verif_hash: str = None,
				*,
				min_years: int = 1,
				params: KDFParams = None
		):
			"""
			This class is designed to be used as a hasher and verifier of user-provided
			passwords for online services. On user registration, their password should be
			hashed with this class and the **public_hash** instance attribute value should
			be stored into a database for comparison when the user attempts to log in.
			This class automatically rehashes passwords on successful verification if the
			security parameters have changed. The default security parameters of this class
			have been chosen such that the hashing process uses 1 GiB of memory and takes
			about 0.5 seconds on a 12-th Gen Intel i7 CPU at 2.2 GHz.

			:param password: A user-provided secret to be hashed.
			:param verif_hash: A previously generated hash to compare the current password hash with.
			:param min_years: How crack resistant the password is required to be, in years.
				Password strength check is disabled when the min_years value is set to zero
				or verif_hash is provided. Defaults to one year for this class.
			:param params: Optional parameters to override the security level of this KDF.

			:raises - pydantic.ValidationError:
				When the class is instantiated with invalid inputs.
			:raises - KDFWeakPasswordError(KDFError, QuantCryptError):
				When **min_years** is >= 1 and the `zxcvbn` library has evaluated
				the provided password to be weaker than the specified requirement.
			:raises - KDFVerificationError(KDFError, QuantCryptError):
				When **verif_hash** is provided and the hashed
				password does not match this verification hash.
			:raises - KDFInvalidHashError(KDFError, QuantCryptError):
				When **verif_hash** is invalid.
			:raises - KDFHashingError(KDFError, QuantCryptError):
				When Argon2 hashing process encounters an unknown error.
			"""
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
		def _default_params() -> KDFParams:
			return KDFParams(
				memory_cost=KDFMemCost.GiB_4,
				parallelism=8,
				time_cost=5,
				hash_len=32,
				salt_len=32
			)

		@InputValidator()
		def __init__(
				self,
				password: str,
				public_salt: str = None,
				*,
				min_years: int = 10,
				params: KDFParams = None
		):
			"""
			This class is designed to be used as a generator of secret keys from user-provided
			passwords for encrypting files with symmetric ciphers like AES. When the user wishes
			to encrypt some data with a human-readable password, the password should be hashed
			with this class and the **secret_key** instance attribute value should be used as the
			key with which to encrypt the data with AES. The **public_salt** instance attribute
			value should be stored with the encrypted data to be able to regenerate the correct
			**secret_key** for data decryption. The default security parameters of this class
			have been chosen such that the hashing process uses 4 GiB of memory and takes
			about 3.0 seconds on a 12-th Gen Intel i7 CPU at 2.2 GHz.

			:param password: A user-provided secret to be hashed.
			:param public_salt: The salt of a previously hashed password.
			:param min_years: How crack resistant the password is required to be, in years.
				Password strength check is disabled when the min_years value is set to zero
				or public_salt is provided. Defaults to ten years for this class.
			:param params: Optional parameters to override the security level of this KDF.

			:raises - pydantic.ValidationError:
				When the class is instantiated with invalid inputs.
			:raises - KDFWeakPasswordError(KDFError, QuantCryptError):
				When **min_years** is >= 1 and the `zxcvbn` library has evaluated
				the provided password to be weaker than the specified requirement.
			:raises - KDFHashingError(KDFError, QuantCryptError):
				When Argon2 hashing process encounters an unknown error.
			"""
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
