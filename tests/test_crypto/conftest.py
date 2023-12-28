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
from functools import lru_cache
from typing import Callable


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
	def closure(signature: bytes, min_size: int):
		return [
			str(signature),  # not bytes
			signature[:min_size - 1]  # too short
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
