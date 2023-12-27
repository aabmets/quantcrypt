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
from .common import BasePubkeyAlgorithm
from ..errors import *


@dataclass
class KemByteParams:
	sk_size: int
	pk_size: int
	ct_size: int
	ss_size: int


class BaseKEM(BasePubkeyAlgorithm, ABC):
	@property
	def params(self):
		root = f"{self.namespace}_CRYPTO"
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

		func = getattr(self._lib, self.namespace + "_crypto_kem_keypair")
		if 0 != func(public_key, secret_key):
			raise KeygenFailedError

		pk = ffi.buffer(public_key, kbp.pk_size)
		sk = ffi.buffer(secret_key, kbp.sk_size)
		return bytes(pk), bytes(sk)

	def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
		self.validate(public_key, self.params.pk_size, "public_key")

		ffi = FFI()
		cipher_text = ffi.new(f"uint8_t [{self.params.ct_size}]")
		shared_secret = ffi.new(f"uint8_t [{self.params.ss_size}]")

		func = getattr(self._lib, self.namespace + "_crypto_kem_enc")
		if 0 != func(cipher_text, shared_secret, public_key):
			raise EncapsFailedError

		ct = ffi.buffer(cipher_text, self.params.ct_size)
		ss = ffi.buffer(shared_secret, self.params.ss_size)
		return bytes(ct), bytes(ss)

	def decaps(self, secret_key: bytes, cipher_text: bytes) -> bytes:
		self.validate(secret_key, self.params.sk_size, "secret_key")
		self.validate(cipher_text, self.params.ct_size, "cipher_text")

		ffi = FFI()
		shared_secret = ffi.new(f"uint8_t [{self.params.ss_size}]")

		func = getattr(self._lib, self.namespace + "_crypto_kem_dec")
		if 0 != func(shared_secret, cipher_text, secret_key):
			raise DecapsFailedError

		ss = ffi.buffer(shared_secret, self.params.ss_size)
		return bytes(ss)


class KEM:
	class Kyber(BaseKEM):
		@property
		def name(self) -> str:
			return "kyber1024"
