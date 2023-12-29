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
import platform
import importlib
from cffi import FFI
from enum import Enum
from types import ModuleType
from pydantic import Field
from functools import lru_cache
from typing import Literal, Type, Annotated
from abc import ABC, abstractmethod
from quantcrypt.errors import *


__all__ = [
	"Variant",
	"BaseParamSizes",
	"BasePQCAlgorithm"
]


class Variant(Enum):
	CLEAN = "clean"
	AVX2 = "avx2"


class BaseParamSizes:
	def __init__(self, lib: ModuleType, ns: str):
		self.sk_size = getattr(lib, f"{ns}_CRYPTO_SECRETKEYBYTES")
		self.pk_size = getattr(lib, f"{ns}_CRYPTO_PUBLICKEYBYTES")


class BasePQCAlgorithm(ABC):
	_lib: ModuleType
	variant: Variant

	@property
	@abstractmethod
	def name(self) -> str: ...

	@property
	@abstractmethod
	def param_sizes(self) -> BaseParamSizes: ...

	@abstractmethod
	def keygen(self) -> tuple[bytes, bytes]: ...

	@property
	def _namespace(self) -> str:
		name = self.name.replace('-', '').upper()
		return f"PQCLEAN_{name}_{self.variant.name}"

	@lru_cache
	def _import(self, variant: Variant) -> ModuleType:
		return importlib.import_module(
			f"quantcrypt.internal.bin.{platform.system()}" +
			f".{variant.value}.{self.name.replace('-', '_')}"
		).lib

	def __init__(self, variant: Variant = None):
		# variant is None -> auto-select mode
		try:
			_var = variant or Variant.AVX2
			self._lib = self._import(_var)
			self.variant = _var
		except ModuleNotFoundError as ex:
			if variant is None:
				try:
					self._lib = self._import(Variant.CLEAN)
					self.variant = Variant.CLEAN
					return
				except ModuleNotFoundError:
					pass
			elif variant == Variant.AVX2:
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
