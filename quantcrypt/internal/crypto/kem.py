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
from dataclasses import dataclass
from .common import Variant, BasePQCAlgorithm
from ..errors import *


@dataclass
class KemByteParams:
	sk_size: int
	pk_size: int
	ct_size: int
	ss_size: int


class BaseKEM(BasePQCAlgorithm, ABC):
	@property
	def params(self):
		root = f"{self._namespace}_CRYPTO"
		return KemByteParams(
			sk_size=getattr(self._lib, f"{root}_SECRETKEYBYTES"),
			pk_size=getattr(self._lib, f"{root}_PUBLICKEYBYTES"),
			ct_size=getattr(self._lib, f"{root}_CIPHERTEXTBYTES"),
			ss_size=getattr(self._lib, f"{root}_BYTES")
		)

	def keygen(self) -> tuple[bytes, bytes]:
		ffi, kbp = FFI(), self.params
		public_key = ffi.new(f"uint8_t [{kbp.pk_size}]")
		secret_key = ffi.new(f"uint8_t [{kbp.sk_size}]")

		func = getattr(self._lib, self._namespace + "_crypto_kem_keypair")
		if 0 != func(public_key, secret_key):
			raise KeygenFailedError

		pk = ffi.buffer(public_key, kbp.pk_size)
		sk = ffi.buffer(secret_key, kbp.sk_size)
		return bytes(pk), bytes(sk)

	def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
		self._validate(public_key, self.params.pk_size, "public_key")

		ffi = FFI()
		cipher_text = ffi.new(f"uint8_t [{self.params.ct_size}]")
		shared_secret = ffi.new(f"uint8_t [{self.params.ss_size}]")

		func = getattr(self._lib, self._namespace + "_crypto_kem_enc")
		if 0 != func(cipher_text, shared_secret, public_key):
			raise EncapsFailedError

		ct = ffi.buffer(cipher_text, self.params.ct_size)
		ss = ffi.buffer(shared_secret, self.params.ss_size)
		return bytes(ct), bytes(ss)

	def decaps(self, secret_key: bytes, cipher_text: bytes) -> bytes:
		self._validate(secret_key, self.params.sk_size, "secret_key")
		self._validate(cipher_text, self.params.ct_size, "cipher_text")

		ffi = FFI()
		shared_secret = ffi.new(f"uint8_t [{self.params.ss_size}]")

		func = getattr(self._lib, self._namespace + "_crypto_kem_dec")
		if 0 != func(shared_secret, cipher_text, secret_key):
			raise DecapsFailedError

		ss = ffi.buffer(shared_secret, self.params.ss_size)
		return bytes(ss)


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
