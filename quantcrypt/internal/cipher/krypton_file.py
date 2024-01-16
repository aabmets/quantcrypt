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
from typing import Annotated, Optional, Generator, BinaryIO
from collections.abc import Callable
from .krypton import Krypton
from .common import (
	DecryptedData,
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
			callback: Callable = None
	) -> None:
		"""
		:param secret_key: The key which will be used for encryption.
		:param context: Optional field to describe the ciphers purpose.
			Alters the output of internal hash functions. Not a secret.
		:param chunk_size: By default, the chunk size is automatically determined
			from the file size. Providing a value for this argument allows to
			manually override the chunk size.
		:param callback: This callback, when provided, will be called for each
			encrypted ciphertext chunk. No arguments are passed into the callback.
			Useful for updating progress bars.
		"""
		self._secret_key = secret_key
		self._context = context
		self._chunk_size = chunk_size
		self._callback = callback

	@utils.input_validator()
	def encrypt(self, plaintext_file: Path, output_file: Path, header: bytes = b'') -> None:
		"""
		:param plaintext_file: Path to the plaintext file, which must exist.
		:param output_file: Path to the ciphertext file.
			If the file exists, it will be overwritten.
		:param header: Associated Authenticated Data, which is included
			unencrypted into the metadata field of the generated ciphertext file.
		:return: None
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `plaintext_file` does not exist.
		"""
		if not plaintext_file.exists():
			raise FileNotFoundError

		if self._chunk_size is None:
			ptf_size = plaintext_file.stat().st_size
			self._chunk_size = determine_file_chunk_size(ptf_size)

		krypton = Krypton(self._secret_key, self._context, self._chunk_size)
		krypton.begin_encryption(header)

		output_file.unlink(missing_ok=True)
		output_file.touch()

		with open(output_file, 'r+b') as write_file:
			reserved_space = b'0' * (180 + len(header))
			write_file.write(reserved_space)

			with open(plaintext_file, 'rb') as read_file:
				cs_int = self._chunk_size.value
				for chunk in self._read_file_chunks(read_file, cs_int):
					ciphertext = krypton.encrypt(chunk)
					write_file.write(ciphertext)

			write_file.seek(0)
			metadata = self._pack_metadata(krypton, header)
			write_file.write(metadata)

	@utils.input_validator()
	def decrypt(self, ciphertext_file: Path, output_file: Path) -> DecryptedData:
		"""
		Decrypts a file of any size from disk in chunks into a plaintext file.

		:param ciphertext_file: Path to the ciphertext file, which must exist.
		:param output_file: Path to the plaintext file.
			If the file exists, it will be overwritten.
		:return: Instance of DecryptedFileData.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		if not ciphertext_file.exists():
			raise FileNotFoundError

		with open(ciphertext_file, 'rb') as read_file:
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
		return DecryptedData(
			plaintext=None,
			header=header
		)

	@utils.input_validator()
	def decrypt_into_memory(self, ciphertext_file: Path) -> DecryptedData:
		"""
		Decrypts a file of any size from disk in chunks into memory.
		**Note:** Do NOT decrypt large files (>100MB) into memory, use your best judgement.

		:param ciphertext_file: Path to the ciphertext file, which must exist.
		:return: Instance of DecryptedFileData.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		if not ciphertext_file.exists():
			raise FileNotFoundError

		with open(ciphertext_file, 'rb') as read_file:
			cs_int, vdp, header = self._unpack_metadata(read_file)
			krypton = Krypton(self._secret_key, self._context, None)
			setattr(krypton, '_chunk_size', cs_int)

			krypton.begin_decryption(vdp, header)

			plaintext = bytes()
			for chunk in self._read_file_chunks(read_file, cs_int + 1):
				plaintext += krypton.decrypt(chunk)

		krypton.finish_decryption()
		return DecryptedData(
			plaintext=plaintext,
			header=header
		)

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
