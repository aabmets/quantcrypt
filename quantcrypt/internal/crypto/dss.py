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
from pydantic import validate_call
from quantcrypt.errors import *
from .common import *


class DssParamSizes(BaseParamSizes):
	def __init__(self, lib: ModuleType, ns: str):
		self.sig_size = getattr(lib, f"{ns}_CRYPTO_BYTES")
		super().__init__(lib, ns)


class BaseDSS(BasePQCAlgorithm, ABC):
	@property
	@lru_cache
	def param_sizes(self) -> DssParamSizes:
		return DssParamSizes(self._lib, self._namespace)

	def keygen(self) -> tuple[bytes, bytes]:
		return self._keygen("sign")

	def sign(self, secret_key: bytes, message: bytes) -> bytes:
		params = self.param_sizes
		sk_anno = self._bytes_anno(equal_to=params.sk_size)
		msg_anno = self._bytes_anno(min_size=1)

		@validate_call(validate_return=True)
		def _sign(sk: sk_anno, msg: msg_anno) -> bytes:
			ffi = FFI()
			sig_buf = ffi.new(f"uint8_t [{params.sig_size}]")
			sig_len = ffi.new("size_t *", params.sig_size)

			func = getattr(self._lib, self._namespace + f"_crypto_sign_signature")
			if 0 != func(sig_buf, sig_len, msg, len(msg), sk):
				raise DSSSignFailedError

			sig_len = struct.unpack("Q", ffi.buffer(sig_len, 8))[0]
			return bytes(ffi.buffer(sig_buf, sig_len))

		return _sign(secret_key, message)

	def verify(self, public_key: bytes, message: bytes, signature: bytes, *, raises: bool = True) -> bool:
		params = self.param_sizes
		pk_anno = self._bytes_anno(equal_to=params.pk_size)
		sig_anno = self._bytes_anno(max_size=params.sig_size)
		msg_anno = self._bytes_anno(min_size=1)

		@validate_call(validate_return=True)
		def _verify(pk: pk_anno, msg: msg_anno, sig: sig_anno, _raises: bool) -> bool:
			func = getattr(self._lib, self._namespace + f"_crypto_sign_verify")
			result = func(sig, len(sig), msg, len(msg), pk)
			if result != 0 and _raises:
				raise DSSVerifyFailedError
			return result == 0

		return _verify(public_key, message, signature, raises)


class DSS:
	class Dilithium(BaseDSS):
		def __init__(self, variant: Variant = None):
			"""
			Initializes the Dilithium instance with C extension binaries.
			User is able to override which underlying binary is used for the
			instance by providing a Variant enum for the variant parameter.

			:param variant: Which binary to use underneath.
				When variant is None *(auto-select mode)*, quantcrypt will
				first try to import AVX2 binaries. If there are no AVX2 binaries
				for the host platform, it will fall back to using CLEAN binaries.
			:raises ImportError: When an unknown import error has occurred.
			:raises ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
				and quantcrypt cannot find AVX2 binaries for the current platform.
			:raises SystemExit: When quantcrypt cannot find CLEAN binaries for
				the current platform *(any-select mode)*. This is a fatal error
				which requires the library to be reinstalled, because all platforms
				should have CLEAN binaries available.
			"""
			super().__init__(variant)

		@property
		def name(self) -> str:
			return "dilithium5"

	class Falcon(BaseDSS):
		def __init__(self, variant: Variant = None):
			"""
			Initializes the Falcon instance with C extension binaries.
			User is able to override which underlying binary is used for the
			instance by providing a Variant enum for the variant parameter.

			:param variant: Which binary to use underneath.
				When variant is None *(auto-select mode)*, quantcrypt will
				first try to import AVX2 binaries. If there are no AVX2 binaries
				for the host platform, it will fall back to using CLEAN binaries.
			:raises ImportError: When an unknown import error has occurred.
			:raises ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
				and quantcrypt cannot find AVX2 binaries for the current platform.
			:raises SystemExit: When quantcrypt cannot find CLEAN binaries for
				the current platform *(any-select mode)*. This is a fatal error
				which requires the library to be reinstalled, because all platforms
				should have CLEAN binaries available.
			"""
			super().__init__(variant)

		@property
		def name(self) -> str:
			return "falcon-1024"

	class FastSphincs(BaseDSS):
		def __init__(self, variant: Variant = None):
			"""
			Initializes the FastSphincs instance with C extension binaries.
			User is able to override which underlying binary is used for the
			instance by providing a Variant enum for the variant parameter.

			:param variant: Which binary to use underneath.
				When variant is None *(auto-select mode)*, quantcrypt will
				first try to import AVX2 binaries. If there are no AVX2 binaries
				for the host platform, it will fall back to using CLEAN binaries.
			:raises ImportError: When an unknown import error has occurred.
			:raises ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
				and quantcrypt cannot find AVX2 binaries for the current platform.
			:raises SystemExit: When quantcrypt cannot find CLEAN binaries for
				the current platform *(any-select mode)*. This is a fatal error
				which requires the library to be reinstalled, because all platforms
				should have CLEAN binaries available.
			"""
			super().__init__(variant)

		@property
		def name(self) -> str:
			return "sphincs-shake-256f-simple"

	class SmallSphincs(BaseDSS):
		def __init__(self, variant: Variant = None):
			"""
			Initializes the SmallSphincs instance with C extension binaries.
			User is able to override which underlying binary is used for the
			instance by providing a Variant enum for the variant parameter.

			:param variant: Which binary to use underneath.
				When variant is None *(auto-select mode)*, quantcrypt will
				first try to import AVX2 binaries. If there are no AVX2 binaries
				for the host platform, it will fall back to using CLEAN binaries.
			:raises ImportError: When an unknown import error has occurred.
			:raises ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
				and quantcrypt cannot find AVX2 binaries for the current platform.
			:raises SystemExit: When quantcrypt cannot find CLEAN binaries for
				the current platform *(any-select mode)*. This is a fatal error
				which requires the library to be reinstalled, because all platforms
				should have CLEAN binaries available.
			"""
			super().__init__(variant)

		@property
		def name(self) -> str:
			return "sphincs-shake-256s-simple"
