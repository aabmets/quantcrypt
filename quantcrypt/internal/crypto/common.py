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
import re
import base64
import binascii
import platform
import importlib
from cffi import FFI
from enum import Enum
from types import ModuleType
from functools import lru_cache
from pydantic import ConfigDict, Field, validate_call
from typing import Literal, Type, Annotated, Callable
from abc import ABC, abstractmethod
from quantcrypt.errors import *


__all__ = [
	"InputValidator",
	"PQAVariant",
	"BasePQAParamSizes",
	"BasePQAlgorithm",
]


class InputValidator:
	def __new__(cls) -> Callable:
		return validate_call(config=ConfigDict(
			arbitrary_types_allowed=True,
			validate_return=True
		))


class PQAVariant(Enum):
	CLEAN = "clean"
	AVX2 = "avx2"


class BasePQAParamSizes:
	def __init__(self, lib: ModuleType, ns: str):
		self.sk_size = getattr(lib, f"{ns}_CRYPTO_SECRETKEYBYTES")
		self.pk_size = getattr(lib, f"{ns}_CRYPTO_PUBLICKEYBYTES")


class BasePQAlgorithm(ABC):
	_lib: ModuleType
	variant: PQAVariant

	@property
	@abstractmethod
	def name(self) -> str: ...

	@property
	@abstractmethod
	def param_sizes(self) -> BasePQAParamSizes: ...

	@abstractmethod
	def keygen(self) -> tuple[bytes, bytes]: ...

	@property
	def _namespace(self) -> str:
		name = self.name.replace('-', '').upper()
		return f"PQCLEAN_{name}_{self.variant.name}"

	@lru_cache
	def _import(self, variant: PQAVariant) -> ModuleType:
		return importlib.import_module(
			f"quantcrypt.internal.bin.{platform.system()}" +
			f".{variant.value}.{self.name.replace('-', '_')}"
		).lib

	def __init__(self, variant: PQAVariant = None):
		# variant is None -> auto-select mode
		try:
			_var = variant or PQAVariant.AVX2
			self._lib = self._import(_var)
			self.variant = _var
		except ModuleNotFoundError as ex:
			if variant is None:
				try:
					self._lib = self._import(PQAVariant.CLEAN)
					self.variant = PQAVariant.CLEAN
					return
				except ModuleNotFoundError:
					pass
			elif variant == PQAVariant.AVX2:
				raise ex
			raise SystemExit(
				"Quantcrypt Fatal Error:\n"
				"Unable to continue due to missing CLEAN binaries."
			)

	def _keygen(self, algo_type: Literal["kem", "sign"]) -> tuple[bytes, bytes]:
		ffi, params = FFI(), self.param_sizes
		public_key = ffi.new(f"uint8_t [{params.pk_size}]")
		secret_key = ffi.new(f"uint8_t [{params.sk_size}]")

		name = f"_crypto_{algo_type}_keypair"
		func = getattr(self._lib, self._namespace + name)
		if 0 != func(public_key, secret_key):
			raise PQAKeygenFailedError

		pk = ffi.buffer(public_key, params.pk_size)
		sk = ffi.buffer(secret_key, params.sk_size)
		return bytes(pk), bytes(sk)

	@staticmethod
	def _bytes_anno(min_size: int = None, max_size: int = None, equal_to: int = None) -> Type[bytes]:
		return Annotated[bytes, Field(
			min_length=equal_to or min_size,
			max_length=equal_to or max_size,
			strict=True
		)]

	@InputValidator()
	def armor(self, key_bytes: bytes) -> str:
		params = self.param_sizes
		match len(key_bytes):
			case params.sk_size:
				key_type = "SECRET"
			case params.pk_size:
				key_type = "PUBLIC"
			case _:
				raise PQAInvalidInputError
		key_str = base64.b64encode(key_bytes).decode('utf-8')
		max_line_length = 64
		lines = [
			key_str[i:i + max_line_length]
			for i in range(0, len(key_str), max_line_length)
		]
		algo_name = '_'.join(re.findall(
			string=self.__class__.__name__,
			pattern='.[^A-Z]*'
		)).upper()
		header = f"-----BEGIN {algo_name} {key_type} KEY-----\n"
		footer = f"\n-----END {algo_name} {key_type} KEY-----"
		return header + '\n'.join(lines) + footer

	@InputValidator()
	def dearmor(self, armored_key: str) -> bytes:
		header_end = armored_key.find('\n') + 1
		footer_start = armored_key.rfind('\n')
		if -1 in [header_end, footer_start]:
			raise PQAInvalidInputError
		try:
			key_bytes = base64.b64decode(
				armored_key[header_end:footer_start]
				.replace('\n', '').encode('utf-8')
			)
		except binascii.Error:
			raise PQAInvalidInputError
		if len(key_bytes) not in [
			self.param_sizes.sk_size,
			self.param_sizes.pk_size
		]:
			raise PQAInvalidInputError
		return key_bytes
