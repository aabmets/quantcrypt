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
import pytest
from typing import Callable, Type
from functools import lru_cache
from quantcrypt.internal.crypto.common import BasePQCAlgorithm
from quantcrypt.typedefs import *


@pytest.fixture(scope="package")
def invalid_keys() -> Callable:
	@lru_cache
	def closure(key: bytes):
		return [
			str(key),  # not bytes
			key[:-1],  # too short
			key + b'0'  # too long
		]
	return closure


@pytest.fixture(scope="package")
def invalid_messages() -> Callable:
	@lru_cache
	def closure(message: bytes):
		return [
			str(message),  # not bytes
			b'',  # too short
		]
	return closure


@pytest.fixture(scope="package")
def invalid_signatures() -> Callable:
	@lru_cache
	def closure(signature: bytes, max_size: int):
		extra = b'0' * (max_size - len(signature) + 1)
		return [
			str(signature),  # not bytes
			signature + extra  # too long
		]
	return closure


@pytest.fixture(scope="package")
def invalid_ciphertexts() -> Callable:
	@lru_cache
	def closure(ciphertext: bytes):
		return [
			str(ciphertext),  # not bytes
			ciphertext[:-1],  # too short
			ciphertext + b'0'  # too long
		]
	return closure


@pytest.fixture(scope="package")
def pqc_variant_tests():
	def closure(algo_cls: Type[BasePQCAlgorithm]):
		obj = algo_cls()
		assert obj.variant == Variant.CLEAN

		obj = algo_cls(Variant.CLEAN)
		assert obj.variant == Variant.CLEAN

		with pytest.raises(ModuleNotFoundError):
			algo_cls(Variant.AVX2)

	return closure
