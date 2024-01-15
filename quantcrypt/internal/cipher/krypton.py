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
from pathlib import Path
from pydantic import Field
from typing import Annotated, Optional, Literal, Any, Generator
from Cryptodome.Hash import SHA3_512, cSHAKE256
from Cryptodome.Hash.cSHAKE128 import cSHAKE_XOF
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.strxor import strxor
from Cryptodome.Cipher import AES
from collections.abc import Callable
from dataclasses import dataclass
from ..errors import InvalidArgsError
from ..kdf.kmac_kdf import KKDF
from .common import (
	ChunkSizeKB, ChunkSizeMB,
	determine_file_chunk_size
)
from .. import utils
from . import errors


__all__ = ["DecryptedData", "Krypton"]


@dataclass
class DecryptedData:
	plaintext: bytes = None,
	header: bytes = None


class Krypton:
	_secret_key: bytes
	_context: bytes
	_chunk_size: int | None = None
	_mode: Literal["enc", "dec"] | None = None
	_xof: cSHAKE_XOF | None = None
	_data_aes: Any | None = None
	_wrap_aes: Any | None = None
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
		multiple messages with the same secret key and configuration.

		:param secret_key: The key which will be used for the cryptographic operations.
		:param context: Optional field to describe the ciphers purpose.
			Alters the output of internal hash functions. Not a secret.
		:param chunk_size: If provided, enables the automatic padding of
			plaintext chunks to `chunk_size` + 1 byte. Disabled by default.
		:raises - pydantic.ValidationError: On invalid input.
		"""
		self._chunk_size = getattr(chunk_size, "value", None)
		self._secret_key = secret_key
		self._context = SHA3_512.new(
			context + b'krypton'
		).digest()

	def flush(self) -> None:
		"""
		Resets the ciphers internal state.
		Does not clear the `secret_key`, `context` or `chunk_size` values.

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
		:raises - errors.CipherStateError:
			If the cipher is already in encryption or decryption mode.
		"""
		if self._mode is not None:
			raise errors.CipherStateError
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
		of `chunk_size` + 1 byte using the ISO/IEC 7816-4 scheme.
		Note: plaintext length may be shorter than `chunk_size`.

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
			raise errors.CipherStateError
		elif self._chunk_size:
			if len(plaintext) > self._chunk_size:
				raise errors.CipherChunkSizeError
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
			raise errors.CipherStateError
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
			raise errors.CipherStateError
		self._mode = "dec"
		ct, tag, salt = verif_data[:80], verif_data[80:96], verif_data[96:]
		key1, key2, key3 = self._keygen(salt)
		self._create_wrap_aes(key3)
		try:
			pt = self._wrap_aes.decrypt_and_verify(ct, tag)
		except ValueError:
			raise errors.CipherVerifyError
		self._nonce, self._tag = pt[:64], pt[64:]
		self._create_data_aes(key2, header)
		self._create_xof(key1)

	@utils.input_validator()
	def decrypt(self, ciphertext: bytes) -> bytes:
		"""
		Decrypts ciphertext into plaintext. When `chunk_size`
		has been set, attempts to remove ISO/IEC 7816-4 scheme
		padding from all decrypted plaintext chunks, before returning
		the un-padded plaintext. Note: the ciphertext input chunks
		are expected to have a length of `chunk_size` + 1 byte.

		:param ciphertext: The ciphertext bytes to be decrypted
		:return: The decrypted plaintext
		:raises - pydantic.ValidationError: On invalid input.
		:raises - errors.CipherStateError:
			If the decryption process has not begun.
		:raises - errors.CipherChunkSizeError:
			If `chunk_size` has been set and ciphertext
			input length is not `chunk_size` + 1 byte.
		:raises - errors.CipherPaddingError:
			If `chunk_size` has been set and the padding of
			the decrypted plaintext is incorrect (corrupted).
		"""
		if self._mode != "dec":
			raise errors.CipherStateError
		elif self._chunk_size and len(ciphertext) != self._chunk_size + 1:
			raise errors.CipherChunkSizeError
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
				raise errors.CipherPaddingError
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
			raise errors.CipherStateError
		try:
			self._data_aes.verify(self._tag)
		except ValueError:
			raise errors.CipherVerifyError
		self.flush()

	@classmethod
	@utils.input_validator()
	def encrypt_file(
			cls,
			secret_key: Annotated[bytes, Field(min_length=64, max_length=64)],
			plaintext_file: Path,
			output_file: Path,
			header: bytes = b'',
			context: Annotated[Optional[bytes], Field(default=b'')] = b'',
			chunk_size: ChunkSizeKB | ChunkSizeMB | None = None,
			callback: Callable = None
	) -> None:
		"""
		Encrypts a file of any size on disk in chunks.

		:param secret_key: The key which will be used for encryption.
		:param plaintext_file: Path to the plaintext file, which must exist.
		:param output_file: Path to the ciphertext file.
			If the file exists, it will be overwritten.
		:param header: Associated Authenticated Data, which is included
			unencrypted into the metadata field of the generated ciphertext file.
		:param context: Optional field to describe the ciphers purpose.
			Alters the output of internal hash functions. Not a secret.
		:param chunk_size: By default, the chunk size is automatically determined
			from the file size. Providing a value for this argument allows to
			manually override the chunk size.
		:param callback: This callback, when provided, will be called for each
			encrypted ciphertext chunk. No arguments are passed into the callback.
			Useful for updating progress bars.
		:return: None
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `plaintext_file` does not exist.
		"""
		if not plaintext_file.exists():
			raise FileNotFoundError

		if chunk_size is None:
			ptf_size = plaintext_file.stat().st_size
			chunk_size = determine_file_chunk_size(ptf_size)

		krypton = cls(secret_key, context, chunk_size)
		krypton.begin_encryption(header)

		with open(plaintext_file, 'rb') as in_file:
			output_file.unlink(missing_ok=True)
			output_file.touch()
			with open(output_file, 'r+b') as out_file:
				reserved_space = b'0' * (180 + len(header))
				out_file.write(reserved_space)
				while True:
					chunk = in_file.read(chunk_size.value)
					if not chunk:
						break
					ciphertext = krypton.encrypt(chunk)
					out_file.write(ciphertext)  # chunk_size + 1 byte
					if callback:
						callback()
				out_file.seek(0)

				h_len = f"{len(header):0>10}".encode("utf-8")  # 10 bytes
				cs = f"{chunk_size.value:0>10}".encode("utf-8")  # 10 bytes
				vdp = krypton.finish_encryption()  # 160 bytes

				out_file.write(h_len + cs + vdp)  # 180 bytes
				out_file.write(header)  # len(header) bytes

	@classmethod
	@utils.input_validator()
	def decrypt_file(
			cls,
			secret_key: Annotated[bytes, Field(min_length=64, max_length=64)],
			ciphertext_file: Path,
			output_file: Path | None = None,
			context: Annotated[Optional[bytes], Field(default=b'')] = b'',
			callback: Callable = None,
			*,
			into_memory: bool = False
	) -> DecryptedData:
		"""
		Decrypts a file of any size on disk in chunks. The user must provide either
		a path for the `output_file` parameter, where the decrypted plaintext will be
		written to, or the `in_memory` argument must be set **True**, which will cause
		the entire plaintext to be decrypted into memory and be returned by this method.
		**Note:** Do NOT decrypt large files (>100MB) into memory, use your best judgement.

		:param secret_key: The key which will be used for encryption.
		:param ciphertext_file: Path to the ciphertext file, which must exist.
		:param output_file: Path to the plaintext file, optional.
			If the file exists, it will be overwritten.
		:param context: Optional field to describe the ciphers purpose.
			Alters the output of internal hash functions. Not a secret.
		:param callback: This callback, when provided, will be called for each
			decrypted plaintext chunk. No arguments are passed into the callback.
			Useful for updating progress bars.
		:param into_memory: Whether the decrypted plaintext chunks should be collected
			and joined together in memory to be returned as a single bytes object.
		:return: Plaintext bytes or None.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		:raises - errors.InvalidArgsError: If neither `output_file` nor `in_memory`
			have been provided to the method call.
		"""
		if not ciphertext_file.exists():
			raise FileNotFoundError
		elif not output_file and not into_memory:
			raise InvalidArgsError

		def _decrypted_chunk() -> Generator[bytes, None, None]:
			while True:
				_chunk = in_file.read(cs_int + 1)
				if not _chunk:
					break
				_pt = krypton.decrypt(_chunk)
				if callback:
					callback()
				yield _pt

		with open(ciphertext_file, 'rb') as in_file:
			data = in_file.read(180)
			h_len, cs, vdp = data[:10], data[10:20], data[20:180]
			h_len_int = int(h_len.decode("utf-8"))
			header = in_file.read(h_len_int)

			cs_int = int(cs.decode("utf-8"))
			krypton = cls(secret_key, context, None)
			setattr(krypton, '_chunk_size', cs_int)

			krypton.begin_decryption(vdp, header)
			plaintext = None

			if into_memory:
				plaintext = bytes()
				for chunk in _decrypted_chunk():
					plaintext += chunk
			else:
				output_file.unlink(missing_ok=True)
				output_file.touch()
				with output_file.open("wb") as out_file:
					for chunk in _decrypted_chunk():
						out_file.write(chunk)

			krypton.finish_decryption()
			return DecryptedData(
				plaintext=plaintext,
				header=header
			)
