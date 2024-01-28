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
from typing import Type, Callable, Optional
from .krypton_file import KryptonFile
from ..kdf.common import KDFParams, MemCost
from ..kdf.argon2_kdf import Argon2
from ..chunksize import ChunkSize
from ..pqa.kem import BaseKEM
from .. import utils


__all__ = ["KryptonKEM"]


class KryptonKEM:
	_testing: bool = False

	@property
	def _kdf_params(self) -> KDFParams:
		if isinstance(self._kdf_overrides, KDFParams):
			return self._kdf_overrides
		default = KDFParams(
			memory_cost=MemCost.GB(1),
			parallelism=8,
			time_cost=1,
			hash_len=64,
			salt_len=32
		)
		if self._testing:
			default.memory_cost = 2 ** 10
		return default

	@utils.input_validator()
	def __init__(
			self,
			kem_class: Type[BaseKEM],
			kdf_params: KDFParams = None,
			context: bytes = b"quantcrypt",
			callback: Optional[Callable] = None,
			chunk_size: ChunkSize.Atd = None
	) -> None:
		"""
		Creates a new KryptonKEM instance for encrypting and/or decrypting
		multiple files of arbitrary sizes with KEM public and private keys
		using the same configuration. Internally uses **KryptonFile** class.

		:param kem_class: BaseKEM class to use for key encaps / decaps.
		:param kdf_params: Alternative security parameters for the Argon2.Key class for
			extending the 32 byte KEM shared secret into a 64 byte secret key, optional.
			The default params have been chosen such that the hashing process uses 2 GiB
			of memory and takes about 0.5 seconds on a 12-th Gen Intel i7 CPU at 2.2 GHz.
		:param context: Optional field to describe the ciphers purpose.
			Alters the output of internal hash functions. Not a secret.
		:param chunk_size: By default, the chunk size is automatically determined
			from the plaintext file size. Providing a value for this argument allows
			to manually override the chunk size.
		:param callback: This callback, when provided, will be called for each
			data chunk that is processed. No arguments are passed into the callback.
			Useful for updating progress bars.
		"""
		self._kdf_overrides = kdf_params
		self._chunk_size = chunk_size
		self._kem_class = kem_class
		self._callback = callback
		self._context = context

	@utils.input_validator()
	def encrypt(
			self,
			public_key: str | bytes,
			data_file: str | Path,
			output_file: str | Path = None
	) -> None:
		"""
		Uses the KEM `public_key` to encapsulate a 32 byte internally generated
		shared secret into a KEM ciphertext, which is added as a header to the
		`output_file`. The shared secret is transformed with Argon2.Key into a 64
		byte symmetric secret key for the Krypton cipher. Then, the plaintext data
		is read from the `data_file` in chunks and encrypted into ciphertext,
		writing the encrypted ciphertext chunks into the `output_file`.

		:param public_key: The public key corresponding to the secret key
			of the KEM algorithm which was used to generate the keypair.
			If the key is a string, it is expected to be in ASCII armor format.
		:param data_file: Path to the plaintext file, which must exist.
			If the path is relative, it is evaluated from the Current Working Directory.
		:param output_file: Path to the ciphertext file. If the path is relative,
			it is evaluated from the Current Working Directory. If not provided,
			it will be created next to the plaintext file with the `kptn` suffix.
			If the file exists, it will be overwritten.
		:return: None
		:raises - FileNotFoundError: If the `plaintext_file` does not exist.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - errors.PQAKeyArmorError: If `public_key` is a string
			and QuantCrypt is unable to successfully de-armor the key.
		:raises - errors.KEMEncapsFailedError: When the underlying
			CFFI library has failed to encapsulate the shared
			secret for any reason.
		"""
		_in_file = utils.resolve_relpath(data_file)
		if not _in_file.is_file():
			raise FileNotFoundError(_in_file)

		if output_file is None:
			_out_file = _in_file.with_suffix(".kptn")
		else:
			_out_file = utils.resolve_relpath(output_file)

		kem = self._kem_class()

		if isinstance(public_key, str):
			public_key = kem.dearmor(public_key)

		pk_atd = utils.annotated_bytes(
			equal_to=kem.param_sizes.pk_size
		)

		@utils.input_validator()
		def _encrypt(_public_key: pk_atd) -> None:
			kem_ct, ss = kem.encaps(_public_key)
			argon = Argon2.Key(
				params=self._kdf_params,
				password=ss
			)
			kf = KryptonFile(
				secret_key=argon.secret_key,
				chunk_size=self._chunk_size,
				callback=self._callback,
				context=self._context
			)
			header = self._pack_header(argon, _in_file, kem_ct)
			kf.encrypt(_in_file, _out_file, header=header)

		_encrypt(public_key)

	@utils.input_validator()
	def decrypt_to_file(
			self,
			secret_key: str | bytes,
			encrypted_file: str | Path,
			output_file: str | Path = None
	) -> None:
		"""
		Uses the KEM `secret_key` to decapsulate the 32 byte shared secret from
		the header of the `encrypted_file`, which is then transformed with Argon2.Key
		into a 64 byte symmetric secret key for the Krypton cipher. Then, the ciphertext
		is read from the `encrypted_file` in chunks and decrypted into plaintext,
		writing the decrypted plaintext chunks into the `output_file`.

		:param secret_key: The secret key corresponding to the public key
			of the KEM algorithm which was used to generate the keypair.
			If the key is a string, it is expected to be in ASCII armor format.
		:param encrypted_file: Path to the ciphertext data file, which must exist.
			If the path is relative, it is evaluated from the Current Working Directory.
		:param output_file: Path to the plaintext file. If the path is relative,
			it is evaluated from the Current Working Directory. If not provided,
			the file will be given the name of the original plaintext file.
			If the file exists, it will be overwritten.
		:return: Header bytes (Associated Authenticated Data).
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - errors.PQAKeyArmorError: If `public_key` is a string
			and QuantCrypt is unable to successfully de-armor the key.
		:raises - errors.KEMDecapsFailedError: When the underlying
			CFFI library has failed to decapsulate the shared
			secret from the ciphertext for any reason.
		"""
		in_file, kf = self._kf_decrypt(secret_key, encrypted_file)
		if output_file is None:
			_out_file = self._unpack_header(in_file)[0]
		else:
			_out_file = utils.resolve_relpath(output_file)

		kf.decrypt_to_file(in_file, _out_file)

	@utils.input_validator()
	def decrypt_to_memory(
			self,
			secret_key: str | bytes,
			encrypted_file: str | Path
	) -> bytes:
		"""
		Uses the KEM `secret_key` to decapsulate the 32 byte shared secret from
		the header of the `encrypted_file`, which is then transformed with Argon2.Key
		into a 64 byte symmetric secret key for the Krypton cipher. Then, the ciphertext
		is read from the `encrypted_file` in chunks and decrypted into plaintext,
		storing the entire decrypted plaintext into memory. **Note:** Do NOT decrypt
		huge files (>100MB) into memory, use your best judgement.

		:param secret_key: The secret key corresponding to the public key
			of the KEM algorithm which was used to generate the keypair.
			If the key is a string, it is expected to be in ASCII armor format.
		:param encrypted_file: Path to the ciphertext data file, which must exist.
			If the path is relative, it is evaluated from the Current Working Directory.
		:return: Header bytes (Associated Authenticated Data).
		:raises - FileNotFoundError: If the `ciphertext_file` does not exist.
		:raises - pydantic.ValidationError: On invalid input.
		:raises - errors.PQAKeyArmorError: If `public_key` is a string
			and QuantCrypt is unable to successfully de-armor the key.
		:raises - errors.KEMDecapsFailedError: When the underlying
			CFFI library has failed to decapsulate the shared
			secret from the ciphertext for any reason.
		"""
		in_file, kf = self._kf_decrypt(secret_key, encrypted_file)
		dec_data = kf.decrypt_to_memory(in_file)
		return dec_data.plaintext

	def _kf_decrypt(self, secret_key: str | bytes, ciphertext_file: str | Path) -> tuple[Path, KryptonFile]:
		_in_file = utils.resolve_relpath(ciphertext_file)
		if not _in_file.is_file():
			raise FileNotFoundError(_in_file)

		kem = self._kem_class()

		if isinstance(secret_key, str):
			secret_key = kem.dearmor(secret_key)

		sk_atd = utils.annotated_bytes(
			equal_to=kem.param_sizes.sk_size
		)

		@utils.input_validator()
		def _inner(_secret_key: sk_atd) -> tuple[Path, KryptonFile]:
			_, salt, kem_ct = self._unpack_header(_in_file)
			ss = kem.decaps(_secret_key, kem_ct)
			argon = Argon2.Key(
				params=self._kdf_params,
				public_salt=salt,
				password=ss
			)
			return _in_file, KryptonFile(
				secret_key=argon.secret_key,
				chunk_size=self._chunk_size,
				callback=self._callback,
				context=self._context
			)
		return _inner(secret_key)

	@staticmethod
	def _pack_header(argon: Argon2.Key, in_file: Path, kem_ct: bytes) -> bytes:
		salt = utils.b64(argon.public_salt)
		file_name = in_file.name.encode("utf-8")
		fn_len = f"{len(file_name):0>4}".encode("utf-8")
		return fn_len + file_name + salt + kem_ct

	@staticmethod
	def _unpack_header(in_file: Path) -> tuple[str, bytes, bytes]:
		header = KryptonFile.read_file_header(in_file)
		fn_len = int(header[:4].decode("utf-8"))
		s1, s2, s3 = 4, 4 + fn_len, 36 + fn_len
		orig_name = header[s1:s2].decode("utf-8")
		salt, kem_ct = header[s2:s3], header[s3:]
		return orig_name, salt, kem_ct
