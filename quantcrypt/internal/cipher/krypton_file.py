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
from dataclasses import dataclass
from collections.abc import Callable
from typing import Annotated, Optional, BinaryIO
from ..chunksize import ChunkSize
from .krypton import Krypton
from .. import utils


__all__ = ["DecryptedFile", "KryptonFile"]


@dataclass
class DecryptedFile:
	"""
	Available instance attributes:
	1) plaintext - bytes
	2) header - bytes
	"""
	plaintext: bytes
	header: bytes


class KryptonFile:
	@utils.input_validator()
	def __init__(
			self,
			secret_key: Annotated[bytes, Field(min_length=64, max_length=64)],
			context: Annotated[Optional[bytes], Field(default=b'')] = b'',
			callback: Optional[Callable] = None,
			chunk_size: ChunkSize.Atd = None
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
	def encrypt(self, data_file: str | Path, output_file: str | Path, header: bytes = b'') -> None:
		"""
		Reads plaintext from the `data_file` in chunks and encrypts them into
		ciphertext, writing the encrypted ciphertext chunks into the output_file.
		The header data is also written into the `output_file`.

		:param data_file: An absolute path to the plaintext data file, which must exist.
		:param output_file: An absolute path to the ciphertext file.
			If the file exists, it will be overwritten.
		:param header: Associated Authenticated Data, which is included
			unencrypted into the metadata field of the generated ciphertext file.
		:return: None
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `plaintext_file` does not exist.
		"""
		_data_file = Path(data_file)
		_output_file = Path(output_file)

		if not _data_file.is_file():
			raise FileNotFoundError(_data_file)

		if self._chunk_size is None:
			ptf_size = _data_file.stat().st_size
			self._chunk_size = ChunkSize.determine_from_data_size(ptf_size)

		krypton = Krypton(self._secret_key, self._context, self._chunk_size)
		krypton.begin_encryption(header)

		_output_file.unlink(missing_ok=True)
		_output_file.touch()

		with open(_output_file, 'r+b') as write_file:
			reserved_space = b'0' * (180 + len(header))
			write_file.write(reserved_space)

			with open(_data_file, 'rb') as read_file:
				cs_int = self._chunk_size.value
				for chunk in utils.read_file_chunks(read_file, cs_int, self._callback):
					ciphertext = krypton.encrypt(chunk)
					write_file.write(ciphertext)

			write_file.seek(0)
			metadata = self._pack_metadata(krypton, header)
			write_file.write(metadata)

	@utils.input_validator()
	def decrypt_to_file(self, encrypted_file: str | Path, output_file: str | Path) -> bytes:
		"""
		Reads ciphertext from the `encrypted_file` in chunks and decrypts them
		into plaintext, writing the decrypted plaintext chunks into the output_file.
		The header data can be considered authenticated when the decryption
		process has completed successfully.

		:param encrypted_file: Path to the ciphertext data file, which must exist.
			If the path is relative, it is evaluated from the Current Working Directory.
		:param output_file: An absolute path to the plaintext file.
			If the file exists, it will be overwritten.
		:return: Header bytes (Associated Authenticated Data).
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		_in_file = utils.resolve_relpath(encrypted_file)
		if not _in_file.is_file():
			raise FileNotFoundError(_in_file)

		with open(_in_file, 'rb') as read_file:
			cs_int, vdp, header = self._unpack_metadata(read_file)
			krypton = Krypton(self._secret_key, self._context, None)
			setattr(krypton, '_chunk_size', cs_int)

			krypton.begin_decryption(vdp, header)

			_output_file = Path(output_file)
			_output_file.unlink(missing_ok=True)
			_output_file.touch()

			with _output_file.open("wb") as write_file:
				for chunk in utils.read_file_chunks(read_file, cs_int + 1, self._callback):
					plaintext = krypton.decrypt(chunk)
					write_file.write(plaintext)

		krypton.finish_decryption()
		return header

	@utils.input_validator()
	def decrypt_to_memory(self, encrypted_file: str | Path) -> DecryptedFile:
		"""
		Reads ciphertext from the `encrypted_file` in chunks and decrypts
		them into plaintext, storing the entire decrypted plaintext into memory.
		The header data can be considered authenticated when the decryption
		process has completed successfully. **Note:** Do NOT decrypt large
		files (>100MB) into memory, use your best judgement.

		:param encrypted_file: An absolute path to the ciphertext data file, which must exist.
		:return: Instance of DecryptedFileData.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		_encrypted_file = Path(encrypted_file)

		if not _encrypted_file.is_file():
			raise FileNotFoundError(_encrypted_file)

		with open(_encrypted_file, 'rb') as read_file:
			cs_int, vdp, header = self._unpack_metadata(read_file)
			krypton = Krypton(self._secret_key, self._context, None)
			setattr(krypton, '_chunk_size', cs_int)

			krypton.begin_decryption(vdp, header)

			plaintext = bytes()
			for chunk in utils.read_file_chunks(read_file, cs_int + 1, self._callback):
				plaintext += krypton.decrypt(chunk)

		krypton.finish_decryption()
		return DecryptedFile(
			plaintext=plaintext,
			header=header
		)

	@classmethod
	@utils.input_validator()
	def read_file_header(cls, encrypted_file: str | Path) -> bytes:
		"""
		Reads the header bytes from a Krypton ciphertext file.
		The header data can be considered authenticated when
		the file decryption process has completed successfully.

		:param encrypted_file: An absolute path to the ciphertext file, which must exist.
		:return: Header bytes (Associated Authenticated Data).
		:raises - pydantic.ValidationError: On invalid input.
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		"""
		_encrypted_file = Path(encrypted_file)

		if not _encrypted_file.exists():
			raise FileNotFoundError

		with open(_encrypted_file, 'rb') as read_file:
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
