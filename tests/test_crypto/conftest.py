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
from pydantic import ValidationError
from typing import Callable, Type, cast
from quantcrypt.internal.crypto.common import BasePQAlgorithm
from quantcrypt.errors import InvalidArgsError
from quantcrypt.utils import *


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
	def closure(algo_cls: Type[BasePQAlgorithm]):
		obj = algo_cls()
		assert obj.variant == PQAVariant.CLEAN

		obj = algo_cls(PQAVariant.CLEAN)
		assert obj.variant == PQAVariant.CLEAN

		with pytest.raises(ModuleNotFoundError):
			algo_cls(PQAVariant.AVX2)

	return closure


@pytest.fixture(name="armoring_success_tests", scope="package")
def fixture_armoring_success_tests():
	def closure(kem_cls: Type[BasePQAlgorithm]):
		kem = kem_cls()
		public_key, secret_key = kem.keygen()

		apk = kem.armor(public_key)
		assert apk.startswith("-----BEGIN")
		assert apk.endswith("PUBLIC KEY-----")

		ask = kem.armor(secret_key)
		assert ask.startswith("-----BEGIN")
		assert ask.endswith("SECRET KEY-----")

		pkb = kem.dearmor(apk)
		assert pkb == public_key

		skb = kem.dearmor(ask)
		assert skb == secret_key

	return closure


@pytest.fixture(name="armor_failure_tests", scope="package")
def fixture_armor_failure_tests():
	def closure(kem_cls: Type[BasePQAlgorithm]):
		kem = kem_cls()
		public_key, secret_key = kem.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				kem.armor(cast(key(), bytes))

		for key in [public_key + b'x', public_key[:-1]]:
			with pytest.raises(InvalidArgsError):
				kem.armor(key)

		for key in [secret_key + b'x', secret_key[:-1]]:
			with pytest.raises(InvalidArgsError):
				kem.armor(key)

	return closure


@pytest.fixture(name="dearmor_failure_tests", scope="package")
def fixture_dearmor_failure_tests():
	def closure(kem_cls: Type[BasePQAlgorithm]):
		kem = kem_cls()
		public_key, secret_key = kem.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				kem.dearmor(cast(key(), bytes))

		def _reuse_tests(data: list[str]):
			center = len(data) // 2

			with pytest.raises(InvalidArgsError):
				copy = data.copy()
				copy.pop(center)
				kem.dearmor('\n'.join(copy))

			with pytest.raises(InvalidArgsError):
				copy = data.copy()
				copy.insert(center, 'abcd')
				kem.dearmor('\n'.join(copy))

			with pytest.raises(InvalidArgsError):
				copy = data.copy()
				line = copy.pop(center)[:-1] + '!'
				copy.insert(center, line)
				kem.dearmor('\n'.join(copy))

		apk = kem.armor(public_key).split('\n')
		_reuse_tests(apk)

		ask = kem.armor(secret_key).split('\n')
		_reuse_tests(ask)

	return closure
