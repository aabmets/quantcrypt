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
import secrets
from abc import ABC, abstractmethod
from zxcvbn import zxcvbn
from argon2 import PasswordHasher
from typing import Type, Optional
from argon2 import exceptions as aex
from ..errors import InvalidUsageError
from .common import MemCost, KDFParams
from . import errors
from .. import utils


__all__ = ["Argon2"]


class BaseArgon2(ABC):
	_testing: bool = False
	_engine: PasswordHasher
	params: KDFParams

	@staticmethod
	@abstractmethod
	def _default_params() -> KDFParams: ...

	def __init__(self, params: KDFParams | None) -> None:
		if isinstance(params, KDFParams):
			self.params = params
		else:
			self.params = self._default_params()
			if self._testing:
				self.params.memory_cost = 2 ** 10
		self._engine = PasswordHasher(
			**self.params.toDict()
		)

	@staticmethod
	def _assert_crack_resistance(password: str, min_years: int, data_key: str) -> None:
		result: dict = zxcvbn(password)
		data = result["crack_times_seconds"][data_key]
		real_years = int(data) // (365 * 24 * 3600)
		if real_years < min_years:
			raise errors.KDFWeakPasswordError


class Argon2Hash(BaseArgon2):
	public_hash: Optional[str] = None
	rehashed: bool = False
	verified: bool = False

	@staticmethod
	def _default_params() -> KDFParams:
		return KDFParams(
			memory_cost=MemCost.GB(2),
			parallelism=8,
			time_cost=1,
			hash_len=64,
			salt_len=32
		)

	@utils.input_validator()
	def __init__(
			self,
			password: str | bytes,
			verif_hash: str | bytes = None,
			*,
			min_years: int = 1,
			params: KDFParams = None
	) -> None:
		"""
		This class is designed to be used as a hasher and verifier of user-provided
		passwords for online services. On user registration, their password should be
		hashed with this class and the **public_hash** instance attribute value should
		be stored into a database for comparison when the user attempts to log in.
		This class automatically rehashes passwords on successful verification if the
		security parameters have changed. The default security parameters of this class
		have been chosen such that the hashing process uses 2 GiB of memory and takes
		about 0.5 seconds on a 12-th Gen Intel i7 CPU at 2.2 GHz.

		:param password: A user-provided secret to be hashed.
		:param verif_hash: A previously generated hash to compare the current password hash with.
		:param min_years: How crack resistant the password is required to be, in years.
			Defaults to one year for this class. Password strength check is disabled,
			when **password** is an instance of bytes, **min_years** value is set to
			zero or **public_salt** is provided.
		:param params: Optional parameters to override the security level of this KDF.

		:raises - pydantic.ValidationError:
			When the class is instantiated with invalid inputs.
		:raises - errors.KDFWeakPasswordError:
			When password strength check is enabled and the `zxcvbn` library has evaluated
			the provided password to be weaker than the specified requirement.
		:raises - errors.KDFVerificationError:
			When **verif_hash** is provided and the hashed
			password does not match this verification hash.
		:raises - errors.KDFInvalidHashError:
			When **verif_hash** is invalid.
		:raises - errors.KDFHashingError:
			When Argon2 hashing process encounters an unknown error.
		"""
		if isinstance(password, str) and not verif_hash and min_years > 0:
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
			raise errors.KDFVerificationError
		except aex.InvalidHashError:
			raise errors.KDFInvalidHashError
		except aex.HashingError:  # pragma: no cover
			raise errors.KDFHashingError


class Argon2Key(BaseArgon2):
	secret_key: Optional[bytes] = None
	public_salt: Optional[str] = None

	@staticmethod
	def _default_params() -> KDFParams:
		return KDFParams(
			memory_cost=MemCost.GB(8),
			parallelism=8,
			time_cost=4,
			hash_len=64,
			salt_len=32
		)

	@utils.input_validator()
	def __init__(
			self,
			password: str | bytes,
			public_salt: str | bytes = None,
			*,
			min_years: int = 10,
			params: KDFParams = None
	) -> None:
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

		:param password: The user-provided low-entropy password.
		:param public_salt: A previously generated salt to hash the password with.
			Argon2 will generate the salt if one is not provided. If the salt is
			a string, it is expected to be base64 encoded.
		:param min_years: How crack resistant the password is required to be, in years.
			Defaults to ten years for this class. Password strength check is disabled,
			when **password** is an instance of bytes, **min_years** value is set to
			zero or **public_salt** is provided.
		:param params: Optional parameters to override the security level of this KDF.

		:raises - pydantic.ValidationError:
			When the class is instantiated with invalid inputs.
		:raises - errors.KDFWeakPasswordError:
			When password strength check is enabled and the `zxcvbn` library has evaluated
			the provided password to be weaker than the specified requirement.
		:raises - errors.KDFHashingError:
			When Argon2 hashing process encounters an unknown error.
		"""
		if isinstance(password, str) and not public_salt and min_years > 0:
			data_key = "offline_slow_hashing_1e4_per_second"
			self._assert_crack_resistance(password, min_years, data_key)

		super().__init__(params)
		try:
			if public_salt is None:
				salt_bytes = secrets.token_bytes(self.params.salt_len)
			elif isinstance(public_salt, str):
				salt_bytes = utils.b64(public_salt)
			else:
				salt_bytes = public_salt
			secret_hash = self._engine.hash(
				password, salt=salt_bytes
			)
			_salt, _hash = secret_hash.split('$')[-2:]
			if remainder := len(_hash) % 4:
				_hash += '=' * (4 - remainder)

			self.secret_key = utils.b64(_hash)
			self.public_salt = f"{_salt}="
		except aex.HashingError:  # pragma: no cover
			raise errors.KDFHashingError


class Argon2:
	def __init__(self):
		"""
		This class is a collection of classes and is not
		intended to be instantiated directly. You can access
		the contained **Hash** and **Key** classes as
		attributes of this class.
		"""
		raise InvalidUsageError(
			"Argon2 class is a collection of classes and "
			"is not intended to be instantiated directly."
		)
	Hash: Type[Argon2Hash] = Argon2Hash
	Key: Type[Argon2Key] = Argon2Key
