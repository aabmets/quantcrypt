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
from pydantic import validate_call
from quantcrypt.errors import *
from .common import *


class KemParamSizes(BaseParamSizes):
	def __init__(self, lib: ModuleType, ns: str):
		self.ct_size = getattr(lib, f"{ns}_CRYPTO_CIPHERTEXTBYTES")
		self.ss_size = getattr(lib, f"{ns}_CRYPTO_BYTES")
		super().__init__(lib, ns)


class BaseKEM(BasePQCAlgorithm, ABC):
	@property
	@lru_cache
	def param_sizes(self) -> KemParamSizes:
		return KemParamSizes(self._lib, self._namespace)

	def keygen(self) -> tuple[bytes, bytes]:
		return self._keygen("kem")

	def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
		params = self.param_sizes
		pk_anno = self._bytes_anno(equal_to=params.pk_size)

		@validate_call(validate_return=True)
		def _encaps(pk: pk_anno) -> tuple[bytes, bytes]:
			ffi = FFI()
			cipher_text = ffi.new(f"uint8_t [{params.ct_size}]")
			shared_secret = ffi.new(f"uint8_t [{params.ss_size}]")

			func = getattr(self._lib, self._namespace + "_crypto_kem_enc")
			if 0 != func(cipher_text, shared_secret, pk):
				raise KEMEncapsFailedError

			ct = ffi.buffer(cipher_text, params.ct_size)
			ss = ffi.buffer(shared_secret, params.ss_size)
			return bytes(ct), bytes(ss)

		return _encaps(public_key)

	def decaps(self, secret_key: bytes, cipher_text: bytes) -> bytes:
		params = self.param_sizes
		sk_anno = self._bytes_anno(equal_to=params.sk_size)
		ct_anno = self._bytes_anno(equal_to=params.ct_size)

		@validate_call(validate_return=True)
		def _decaps(sk: sk_anno, ct: ct_anno) -> bytes:
			ffi = FFI()
			shared_secret = ffi.new(f"uint8_t [{params.ss_size}]")

			func = getattr(self._lib, self._namespace + "_crypto_kem_dec")
			if 0 != func(shared_secret, ct, sk):
				raise KEMDecapsFailedError

			ss = ffi.buffer(shared_secret, params.ss_size)
			return bytes(ss)

		return _decaps(secret_key, cipher_text)


class KEM:
	class Kyber(BaseKEM):
		def __init__(self, variant: Variant = None):
			"""
			Initializes the Kyber instance with C extension binaries.
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
			return "kyber1024"
