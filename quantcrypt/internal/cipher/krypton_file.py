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
from pathlib import Path
from pydantic import Field
from collections.abc import Callable
from typing import (
	Annotated, Optional,
	Union, Generator, BinaryIO
)
from .krypton import Krypton
from .common import (
	DecryptedFileData,
	ChunkSizeKB, ChunkSizeMB,
	determine_file_chunk_size
)
from .. import utils


__all__ = ["KryptonFile"]


class KryptonFile:
	@utils.input_validator()
	def __init__(
			self,
			secret_key: Annotated[bytes, Field(min_length=64, max_length=64)],
			context: Annotated[Optional[bytes], Field(default=b'')] = b'',
			chunk_size: ChunkSizeKB | ChunkSizeMB | None = None,
			callback: Union[Callable, None] = None
	) -> None:
		"""
		Creates a new KryptonFile instance for encrypting and/or decrypting multiple
		files of arbitrary sizes with the same secret key using the same configuration.

		:param secret_key: The key which will be used for the cryptographic operations.
		:param context: Optional field to describe the ciphers purpose.
			Alters the output of internal hash functions. Not a secret.
		:param chunk_size: By default, the chunk size is automatically determined
			from the plaintext file size. Providing a value for this argument allows
			to manually override the chunk size.
		:param callback: This callback, when provided, will be called for each
			data chunk that is processed. No arguments are passed into the callback.
			Useful for updating progress bars.
		"""
		self._secret_key = secret_key
		self._context = context
		self._chunk_size = chunk_size
		self._callback = callback

	@utils.input_validator()
	def encrypt(self, data_file: Path, output_file: Path, header: bytes = b'') -> None:
		"""
		Reads plaintext from the `data_file` in chunks and encrypts them into
		ciphertext, writing the encrypted ciphertext chunks into the output_file.
		The header data is also written into the `output_file`.

		:param data_file: Path to the plaintext data file, which must exist.
		:param output_file: Path to the ciphertext file.
			If the file exists, it will be overwritten.
		:param header: Associated Authenticated Data, which is included
			unencrypted into the metadata field of the generated ciphertext file.
		:return: None
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `plaintext_file` does not exist.
		"""
		if not data_file.exists():
			raise FileNotFoundError

		if self._chunk_size is None:
			ptf_size = data_file.stat().st_size
			self._chunk_size = determine_file_chunk_size(ptf_size)

		krypton = Krypton(self._secret_key, self._context, self._chunk_size)
		krypton.begin_encryption(header)

		output_file.unlink(missing_ok=True)
		output_file.touch()

		with open(output_file, 'r+b') as write_file:
			reserved_space = b'0' * (180 + len(header))
			write_file.write(reserved_space)

			with open(data_file, 'rb') as read_file:
				cs_int = self._chunk_size.value
				for chunk in self._read_file_chunks(read_file, cs_int):
					ciphertext = krypton.encrypt(chunk)
					write_file.write(ciphertext)

			write_file.seek(0)
			metadata = self._pack_metadata(krypton, header)
			write_file.write(metadata)

	@utils.input_validator()
	def decrypt_to_file(self, encrypted_file: Path, output_file: Path) -> bytes:
		"""
		Reads ciphertext from the `encrypted_file` in chunks and decrypts them
		into plaintext, writing the decrypted plaintext chunks into the output_file.
		The header data can be considered authenticated when the decryption
		process has completed successfully.

		:param encrypted_file: Path to the ciphertext data file, which must exist.
		:param output_file: Path to the plaintext file.
			If the file exists, it will be overwritten.
		:return: Header bytes (Associated Authenticated Data).
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		if not encrypted_file.exists():
			raise FileNotFoundError

		with open(encrypted_file, 'rb') as read_file:
			cs_int, vdp, header = self._unpack_metadata(read_file)
			krypton = Krypton(self._secret_key, self._context, None)
			setattr(krypton, '_chunk_size', cs_int)

			krypton.begin_decryption(vdp, header)

			output_file.unlink(missing_ok=True)
			output_file.touch()

			with output_file.open("wb") as write_file:
				for chunk in self._read_file_chunks(read_file, cs_int + 1):
					plaintext = krypton.decrypt(chunk)
					write_file.write(plaintext)

		krypton.finish_decryption()
		return header

	@utils.input_validator()
	def decrypt_to_memory(self, encrypted_file: Path) -> DecryptedFileData:
		"""
		Reads ciphertext from the `encrypted_file` in chunks and decrypts
		them into plaintext, storing the entire decrypted plaintext into memory.
		The header data can be considered authenticated when the decryption
		process has completed successfully. **Note:** Do NOT decrypt large
		files (>100MB) into memory, use your best judgement.

		:param encrypted_file: Path to the ciphertext data file, which must exist.
		:return: Instance of DecryptedFileData.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		if not encrypted_file.exists():
			raise FileNotFoundError

		with open(encrypted_file, 'rb') as read_file:
			cs_int, vdp, header = self._unpack_metadata(read_file)
			krypton = Krypton(self._secret_key, self._context, None)
			setattr(krypton, '_chunk_size', cs_int)

			krypton.begin_decryption(vdp, header)

			plaintext = bytes()
			for chunk in self._read_file_chunks(read_file, cs_int + 1):
				plaintext += krypton.decrypt(chunk)

		krypton.finish_decryption()
		return DecryptedFileData(
			plaintext=plaintext,
			header=header
		)

	@classmethod
	@utils.input_validator()
	def read_file_header(cls, encrypted_file: Path) -> bytes:
		"""
		Reads the header bytes from a Krypton ciphertext file.
		The header data can be considered authenticated when
		the file decryption process has completed successfully.

		:param encrypted_file: Path to the ciphertext file, which must exist.
		:return: Header bytes (Associated Authenticated Data).
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		if not encrypted_file.exists():
			raise FileNotFoundError

		with open(encrypted_file, 'rb') as read_file:
			return cls._unpack_metadata(read_file)[2]

	def _pack_metadata(self, krypton: Krypton, header: bytes) -> bytes:
		h_len = f"{len(header):0>10}".encode("utf-8")  # 10 bytes
		cs = f"{self._chunk_size.value:0>10}".encode("utf-8")  # 10 bytes
		vdp = krypton.finish_encryption()  # 160 bytes
		return h_len + cs + vdp + header  # 180 + len(header) bytes

	@staticmethod
	def _unpack_metadata(in_file: BinaryIO):
		data = in_file.read(180)  # 180 bytes
		h_len, cs, vdp = data[:10], data[10:20], data[20:180]  # 10, 10, 160 bytes
		h_len_int = int(h_len.decode("utf-8"))
		cs_int = int(cs.decode("utf-8"))
		header = in_file.read(h_len_int)
		return cs_int, vdp, header

	def _read_file_chunks(self, file: BinaryIO, chunk_size: int) -> Generator[bytes, None, None]:
		while True:
			chunk = file.read(chunk_size)
			if not chunk:
				break
			elif self._callback:
				self._callback()
			yield chunk
