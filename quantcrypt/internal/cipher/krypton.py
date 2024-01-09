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
import secrets
from pydantic import Field
from typing import Annotated, Optional, Literal
from Cryptodome.Cipher import AES
from Cryptodome.Cipher._mode_eax import EaxMode
from Cryptodome.Cipher._mode_siv import SivMode
from Cryptodome.Hash import SHA3_512, cSHAKE256
from Cryptodome.Hash.cSHAKE128 import cSHAKE_XOF
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.strxor import strxor
from ..kdf.kmac_kdf import KKDF
from .. import utils
from .errors import *


__all__ = ["ChunkSize", "Krypton"]


class ChunkSizeKB(dict):
	@utils.input_validator()
	def __init__(self, size: Literal[1, 2, 4, 8, 16, 32, 64, 128, 256, 512]):
		"""
		Converts the size argument kilobytes input value to bytes.
		:param size: The block size in kilobytes
		:return: The block size in bytes
		:raises - pydantic.ValidationError:
			If the input size value is not a valid Literal
		"""
		super().__init__(value=1024 * size)


class ChunkSizeMB(dict):
	@utils.input_validator()
	def __init__(self, size: Literal[1, 2, 4, 8, 16, 32, 64, 128, 256, 512]):
		"""
		Converts the size argument megabytes input value to bytes.
		:param size: The block size in megabytes
		:return: The block size in bytes
		:raises - pydantic.ValidationError:
			If the input size value is not a valid Literal
		"""
		super().__init__(value=1024 ** 2 * size)


class ChunkSize:
	KB = ChunkSizeKB
	MB = ChunkSizeMB


class Krypton:
	_mode: Literal["enc", "dec"] | None = None
	_xof: cSHAKE_XOF | None = None
	_data_aes: EaxMode | None = None
	_wrap_aes: SivMode | None = None
	_nonce: bytes | None = None
	_salt: bytes | None = None
	_tag: bytes | None = None

	@utils.input_validator()
	def __init__(
			self,
			secret_key: Annotated[bytes, Field(min_length=64, max_length=64)],
			context: Annotated[Optional[bytes], Field(default=b'')] = b'',
			chunk_size: ChunkSizeKB | ChunkSizeMB | None = None
	) -> None:
		"""
		Creates a new Krypton instance for encrypting and/or decrypting
		multiple messages with the same secret key.

		:param secret_key: The key which is used for cryptographic operations.
		:param context: Optional field to describe the ciphers purpose.
			Alters the output of internal hash functions. Not a secret.
		:param chunk_size: If provided, enables automatic padding
			of plaintext chunks to `chunk_size` + 1. Disabled by default.
		:raises - pydantic.ValidationError: On invalid input.
		"""
		self._chunk_size = (chunk_size or {}).get("value")
		self._secret_key = secret_key
		self._context = SHA3_512.new(
			context + b'krypton'
		).digest()

	def flush(self) -> None:
		"""
		Resets the ciphers internal state.
		Does not remove `secret_key`, `context`
		or `chunk_size` values.
		:return: None
		"""
		self._mode = None
		self._xof = None
		self._data_aes = None
		self._wrap_aes = None
		self._nonce = None
		self._salt = None
		self._tag = None

	def _keygen(self, salt: bytes) -> tuple[bytes, ...]:
		return KKDF(
			master=self._secret_key,
			context=self._context,
			salt=salt,
			key_len=64,
			num_keys=3
		)

	def _create_xof(self, key: bytes) -> None:
		self._xof = cSHAKE256.new(
			data=key,
			custom=self._context
		)

	def _create_data_aes(self, key: bytes, header: bytes) -> None:
		self._data_aes = AES.new(
			key=key[:32],
			mode=AES.MODE_EAX,
			nonce=self._nonce
		).update(header)

	def _create_wrap_aes(self, key: bytes) -> None:
		self._wrap_aes = AES.new(
			key=key,
			mode=AES.MODE_SIV,
			nonce=self._context
		)

	@utils.input_validator()
	def begin_encryption(self, header: bytes = b'') -> None:
		"""
		Prepares the Krypton instance for encryption mode.
		Generates a random nonce and salt using the `secrets` module,
		initializes the internal cryptographic machinery.

		:param header: Associated Authenticated Data
		:return: None
		:raises - pydantic.ValidationError: On invalid input.
		:raises - CipherStateError:
			If the cipher is already in encryption or decryption mode.
		"""
		if self._mode is not None:
			raise CipherStateError
		self._mode = "enc"
		self._nonce = secrets.token_bytes(64)
		self._salt = secrets.token_bytes(64)
		key1, key2, key3 = self._keygen(self._salt)
		self._create_xof(key1)
		self._create_data_aes(key2, header)
		self._create_wrap_aes(key3)

	@utils.input_validator()
	def encrypt(self, plaintext: bytes) -> bytes:
		"""
		Encrypts plaintext into ciphertext. When `chunk_size`
		has been set, all plaintext is padded to have a length
		of `chunk_size` + 1 using the ISO/IEC 7816-4 scheme.

		:param plaintext: The plaintext bytes to be encrypted
		:return: The encrypted bytes
		:raises - pydantic.ValidationError: On invalid input.
		:raises - errors.CipherStateError:
			If the encryption process has not begun.
		:raises - errors.CipherChunkSizeError:
			If `chunk_size` has been set and plaintext
			length is larger than this value.
		"""
		if self._mode != "enc":
			raise CipherStateError
		elif self._chunk_size:
			if len(plaintext) > self._chunk_size:
				raise CipherChunkSizeError
			plaintext = pad(
				plaintext,
				self._chunk_size + 1,
				style='iso7816'
			)
		mask = self._xof.read(len(plaintext))
		obf_pt = strxor(mask, plaintext)
		return self._data_aes.encrypt(obf_pt)

	def finish_encryption(self) -> bytes:
		"""
		Finalizes the encryption process, creates
		an encrypted verification data packet,
		resets its internal state.

		:return: The encrypted verification data packet
		:raises - CipherStateError:
			If the encryption process has not begun.
		"""
		if self._mode != "enc":
			raise CipherStateError
		salt = self._salt
		ct, tag = self._wrap_aes.encrypt_and_digest(
			self._nonce + self._data_aes.digest()
		)
		self.flush()
		return ct + tag + salt  # 80 + 16 + 64 = 160 bytes

	@utils.input_validator()
	def begin_decryption(
			self,
			verif_data: Annotated[bytes, Field(min_length=160, max_length=160)],
			header: bytes = b''
	) -> None:
		"""
		Prepares the Krypton instance for decryption mode.
		Attempts to decrypt and verify the `verif_data` packet,
		initializes the internal cryptographic machinery.

		:param verif_data: The encrypted verification data packet
		:param header: Associated Authenticated Data
		:return: None
		:raises - pydantic.ValidationError: On invalid input.
		:raises - errors.CipherStateError:
			If the cipher is already in encryption or decryption mode.
		"""
		if self._mode is not None:
			raise CipherStateError
		self._mode = "dec"
		ct, tag, salt = verif_data[:80], verif_data[80:96], verif_data[96:]
		key1, key2, key3 = self._keygen(salt)
		self._create_wrap_aes(key3)
		try:
			pt = self._wrap_aes.decrypt_and_verify(ct, tag)
		except ValueError:
			raise CipherVerifyError
		self._nonce, self._tag = pt[:64], pt[64:]
		self._create_data_aes(key2, header)
		self._create_xof(key1)

	@utils.input_validator()
	def decrypt(self, ciphertext: bytes) -> bytes:
		"""
		Decrypts ciphertext into plaintext. When `chunk_size`
		has been set, attempts to remove ISO/IEC 7816-4 scheme
		padding from all decrypted plaintext chunks, before
		returning the un-padded plaintext.

		:param ciphertext: The ciphertext bytes to be decrypted
		:return: The decrypted plaintext
		:raises - pydantic.ValidationError: On invalid input.
		:raises - errors.CipherStateError:
			If the decryption process has not begun.
		:raises - errors.CipherChunkSizeError:
			If `chunk_size` has been set and ciphertext
			length is larger than `chunk_size` + 1.
		:raises - errors.CipherPaddingError:
			If `chunk_size` has been set and the padding of
			the decrypted plaintext is incorrect (corrupted).
		"""
		if self._mode != "dec":
			raise CipherStateError
		elif self._chunk_size:
			if len(ciphertext) > self._chunk_size + 1:
				raise CipherChunkSizeError
		obf_pt = self._data_aes.decrypt(ciphertext)
		mask = self._xof.read(len(obf_pt))
		plaintext = strxor(mask, obf_pt)
		if self._chunk_size:
			try:
				plaintext = unpad(
					plaintext,
					self._chunk_size + 1,
					style='iso7816'
				)
			except ValueError:
				raise CipherPaddingError
		return plaintext

	def finish_decryption(self) -> None:
		"""
		Finalizes the decryption process, verifies the
		decrypted data digest, resets its internal state.

		:return: None
		:raises - errors.CipherStateError:
			If the decryption process has not begun.
		:raises - errors.CipherVerifyError:
			If the cipher was unable to verify the decrypted data.
		"""
		if self._mode != "dec":
			raise CipherStateError
		try:
			self._data_aes.verify(self._tag)
		except ValueError:
			raise CipherVerifyError
		self.flush()