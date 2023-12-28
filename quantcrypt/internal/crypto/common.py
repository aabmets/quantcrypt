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
from enum import Enum
from typing import Any
from types import ModuleType
from abc import ABC, abstractmethod
from functools import lru_cache
from dataclasses import dataclass
from ..errors import QuantCryptError


class Variant(Enum):
	CLEAN = "clean"
	AVX2 = "avx2"


class BasePubkeyAlgorithm(ABC):
	_lib: ModuleType
	variant: Variant

	@property
	@abstractmethod
	def name(self) -> str: ...

	@property
	@abstractmethod
	def params(self) -> dataclass: ...

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

	@staticmethod
	def _validate(data: Any, exp_size: int, param_name: str) -> None:
		base = f"{param_name} must be of"
		if not isinstance(data, bytes):
			raise QuantCryptError(f"{base} type 'bytes'")
		elif not len(data) == exp_size:
			raise QuantCryptError(f"{base} length {exp_size}")

	def __init__(self):
		try:
			self._lib = self._import(Variant.AVX2)
			self.variant = Variant.AVX2
		except ModuleNotFoundError:
			try:
				self._lib = self._import(Variant.CLEAN)
				self.variant = Variant.CLEAN
			except ModuleNotFoundError:
				raise SystemExit(
					"QuantCryptError: "
					"Unable to continue due to missing binaries."
				)
