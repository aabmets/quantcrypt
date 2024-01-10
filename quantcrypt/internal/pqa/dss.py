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
import struct
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


__all__ = [
	"DSSParamSizes",
	"BaseDSS",
	"Dilithium",
	"Falcon",
	"FastSphincs",
	"SmallSphincs"
]


class DSSParamSizes(BasePQAParamSizes):
	def __init__(self, lib: ModuleType, ns: str):
		self.sig_size = getattr(lib, f"{ns}_CRYPTO_BYTES")
		super().__init__(lib, ns)


class BaseDSS(BasePQAlgorithm, ABC):
	@property
	@lru_cache
	def param_sizes(self) -> DSSParamSizes:
		return DSSParamSizes(self._lib, self._namespace)

	def keygen(self) -> tuple[bytes, bytes]:
		"""
		Generates a tuple of bytes, where the first bytes object is
		the public key and the second bytes object is the secret key.
		:return: tuple of public key bytes and secret key bytes, in this order.
		:raises - errors.DSSKeygenFailedError: When the underlying CFFI
			library has failed to generate the keys for the current
			DSS algorithm for any reason.
		"""
		result = self._keygen("sign")
		if not result:  # pragma: no cover
			raise errors.DSSKeygenFailedError
		return result

	def sign(self, secret_key: bytes, message: bytes) -> bytes:
		"""
		Tries to generate a signature for the message using the secret key.

		:param secret_key: The secret key which is used to sign the provided message.
		:param message: The message for which the signature will be created.
		:return: Bytes of the generated signature.
		:raises - pydantic.ValidationError: When the user-provided
			`secret_key` or `message` values have invalid types or the length
			of the `secret_key` is invalid for the current DSS algorithm.
		:raises - errors.DSSSignFailedError: When the underlying CFFI
			library has failed to generate the signature for any reason.
		"""
		params = self.param_sizes
		sk_anno = self._bytes_anno(equal_to=params.sk_size)
		msg_anno = self._bytes_anno(min_size=1)

		@utils.input_validator()
		def _sign(sk: sk_anno, msg: msg_anno) -> bytes:
			ffi = FFI()
			sig_buf = ffi.new(f"uint8_t [{params.sig_size}]")
			sig_len = ffi.new("size_t *", params.sig_size)

			func = getattr(self._lib, self._namespace + "_crypto_sign_signature")
			if 0 != func(sig_buf, sig_len, msg, len(msg), sk):  # pragma: no cover
				raise errors.DSSSignFailedError

			sig_len = struct.unpack("Q", ffi.buffer(sig_len, 8))[0]
			return bytes(ffi.buffer(sig_buf, sig_len))

		return _sign(secret_key, message)

	def verify(self, public_key: bytes, message: bytes, signature: bytes, *, raises: bool = True) -> bool:
		"""
		Tries to verify the validity of the signature of the message using the public key.

		:param public_key: The public key which is used to
			verify the validity of the signature.
		:param message: The message of which the validity
			of the signature is being verified.
		:param signature: The signature which is being verified
			with the `public_key` for the provided `message`.
		:param raises: Option to disable the raising of the DSSVerifyFailedError,
			which allows the use of an if block to branch logic execution based on
			signature verification success. By default, errors are raised.
		:return: True or False, if `raises` parameter is False, otherwise raises a
			DSSVerifyFailedError on signature verification failure.
		:raises - pydantic.ValidationError: When the user-provided `public_key`,
			`message` or `signature` values have invalid types or when `public_key`
			or `signature` have invalid lengths for the current DSS algorithm.
		:raises - errors.DSSVerifyFailedError: When the underlying CFFI library
			has failed to verify the provided signature for any reason.
		"""
		params = self.param_sizes
		pk_anno = self._bytes_anno(equal_to=params.pk_size)
		sig_anno = self._bytes_anno(max_size=params.sig_size)
		msg_anno = self._bytes_anno(min_size=1)

		@utils.input_validator()
		def _verify(pk: pk_anno, msg: msg_anno, sig: sig_anno, _raises: bool) -> bool:
			func = getattr(self._lib, self._namespace + "_crypto_sign_verify")
			result = func(sig, len(sig), msg, len(msg), pk)
			if result != 0 and _raises:
				raise errors.DSSVerifyFailedError
			return result == 0

		return _verify(public_key, message, signature, raises)


class Dilithium(BaseDSS):
	@utils.input_validator()
	def __init__(self, variant: PQAVariant = None) -> None:
		"""
		Initializes the Dilithium instance with C extension binaries.
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
		return "dilithium5"


class Falcon(BaseDSS):
	@utils.input_validator()
	def __init__(self, variant: PQAVariant = None) -> None:
		"""
		Initializes the Falcon instance with C extension binaries.
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
		return "falcon-1024"


class FastSphincs(BaseDSS):
	@utils.input_validator()
	def __init__(self, variant: PQAVariant = None) -> None:
		"""
		Initializes the FastSphincs instance with C extension binaries.
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
		return "sphincs-shake-256f-simple"


class SmallSphincs(BaseDSS):
	@utils.input_validator()
	def __init__(self, variant: PQAVariant = None) -> None:
		"""
		Initializes the SmallSphincs instance with C extension binaries.
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
		return "sphincs-shake-256s-simple"
