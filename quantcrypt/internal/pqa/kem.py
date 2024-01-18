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
from abc import ABC
from cffi import FFI
from types import ModuleType
from functools import lru_cache
from . import errors
from .. import utils
from .common import (
	BasePQAParamSizes,
	BasePQAlgorithm,
	PQAVariant
)


__all__ = ["KEMParamSizes", "BaseKEM", "Kyber"]


class KEMParamSizes(BasePQAParamSizes):
	def __init__(self, lib: ModuleType, ns: str):
		self.ct_size = getattr(lib, f"{ns}_CRYPTO_CIPHERTEXTBYTES")
		self.ss_size = getattr(lib, f"{ns}_CRYPTO_BYTES")
		super().__init__(lib, ns)


class BaseKEM(BasePQAlgorithm, ABC):
	@property
	@lru_cache
	def param_sizes(self) -> KEMParamSizes:
		return KEMParamSizes(self._lib, self._namespace)

	def keygen(self) -> tuple[bytes, bytes]:
		"""
		Generates a tuple of bytes, where the first bytes object is
		the public key and the second bytes object is the secret key.
		:return: tuple of public key bytes and secret key bytes, in this order.
		:raises - errors.KEMKeygenFailedError: When the underlying CFFI
			library has failed to generate the keys for the current
			KEM algorithm for any reason.
		"""
		result = self._keygen("kem")
		if not result:  # pragma: no cover
			raise errors.KEMKeygenFailedError
		return result

	def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
		"""
		Internally generates a shared secret and then tries to
		encapsulate it into a ciphertext using the provided public key.

		:param public_key: The public key which is used to
			encapsulate the internally generated shared secret.
		:return: tuple of ciphertext bytes and shared secret bytes, in this order.
		:raises - pydantic.ValidationError: When the user-provided
			`public_key` value has invalid type or its length is
			invalid for the current KEM algorithm.
		:raises - errors.KEMEncapsFailedError: When the underlying
			CFFI library has failed to encapsulate the shared
			secret for any reason.
		"""
		params = self.param_sizes
		pk_atd = utils.annotated_bytes(equal_to=params.pk_size)

		@utils.input_validator()
		def _encaps(pk: pk_atd) -> tuple[bytes, bytes]:
			ffi = FFI()
			cipher_text = ffi.new(f"uint8_t [{params.ct_size}]")
			shared_secret = ffi.new(f"uint8_t [{params.ss_size}]")

			func = getattr(self._lib, self._namespace + "_crypto_kem_enc")
			if 0 != func(cipher_text, shared_secret, pk):  # pragma: no cover
				raise errors.KEMEncapsFailedError

			ct = ffi.buffer(cipher_text, params.ct_size)
			ss = ffi.buffer(shared_secret, params.ss_size)
			return bytes(ct), bytes(ss)

		return _encaps(public_key)

	def decaps(self, secret_key: bytes, cipher_text: bytes) -> bytes:
		"""
		Tries to extract the encapsulated shared secret from the
		provided ciphertext using the provided secret key.

		:param secret_key: The secret key which is used to
			decapsulate the provided `cipher_text` bytes object.
		:param cipher_text: The ciphertext from which to extract
			the shared secret using the provided `secret_key`.
		:return: Bytes of the shared secret.
		:raises - pydantic.ValidationError: When the user-provided
			`secret_key` or `cipher_text` values have invalid types
			or their lengths are invalid for the current KEM algorithm.
		:raises - errors.KEMDecapsFailedError: When the underlying
			CFFI library has failed to decapsulate the shared
			secret from the ciphertext for any reason.
		"""
		params = self.param_sizes
		sk_atd = utils.annotated_bytes(equal_to=params.sk_size)
		ct_atd = utils.annotated_bytes(equal_to=params.ct_size)

		@utils.input_validator()
		def _decaps(sk: sk_atd, ct: ct_atd) -> bytes:
			ffi = FFI()
			shared_secret = ffi.new(f"uint8_t [{params.ss_size}]")

			func = getattr(self._lib, self._namespace + "_crypto_kem_dec")
			if 0 != func(shared_secret, ct, sk):  # pragma: no cover
				raise errors.KEMDecapsFailedError

			ss = ffi.buffer(shared_secret, params.ss_size)
			return bytes(ss)

		return _decaps(secret_key, cipher_text)


class Kyber(BaseKEM):
	@utils.input_validator()
	def __init__(self, variant: PQAVariant = None) -> None:
		"""
		Initializes the Kyber instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for
			the current platform *(any-select mode)*. This is a fatal error
			which requires the library to be reinstalled, because all platforms
			should have CLEAN binaries available.
		"""
		super().__init__(variant)

	@property
	def name(self) -> str:
		return "kyber1024"
