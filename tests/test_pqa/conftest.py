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
from quantcrypt.internal.pqa import errors
from quantcrypt.internal.pqa.common import (
	BasePQAlgorithm,
	PQAVariant
)


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


@pytest.fixture(scope="package")
def armoring_success_tests():
	def closure(pqa_cls: Type[BasePQAlgorithm]):
		pqa = pqa_cls()
		public_key, secret_key = pqa.keygen()

		apk = pqa.armor(public_key)
		assert apk.startswith("-----BEGIN")
		assert apk.endswith("PUBLIC KEY-----")

		ask = pqa.armor(secret_key)
		assert ask.startswith("-----BEGIN")
		assert ask.endswith("SECRET KEY-----")

		pkb = pqa.dearmor(apk)
		assert pkb == public_key

		skb = pqa.dearmor(ask)
		assert skb == secret_key

	return closure


@pytest.fixture(scope="package")
def armor_failure_tests():
	def closure(pqa_cls: Type[BasePQAlgorithm]):
		pqa = pqa_cls()
		public_key, secret_key = pqa.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				pqa.armor(cast(key(), bytes))

		for key in [public_key + b'x', public_key[:-1]]:
			with pytest.raises(errors.PQAKeyArmorError):
				pqa.armor(key)

		for key in [secret_key + b'x', secret_key[:-1]]:
			with pytest.raises(errors.PQAKeyArmorError):
				pqa.armor(key)

	return closure


@pytest.fixture(scope="package")
def dearmor_failure_tests():
	def closure(pqa_cls: Type[BasePQAlgorithm]):
		pqa = pqa_cls()
		public_key, secret_key = pqa.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				pqa.dearmor(cast(key(), bytes))

		def _reuse_tests(data: list[str]):
			center = len(data) // 2

			with pytest.raises(errors.PQAKeyArmorError):
				copy = data.copy()
				copy.pop(center)
				pqa.dearmor('\n'.join(copy))

			with pytest.raises(errors.PQAKeyArmorError):
				copy = data.copy()
				copy.insert(1, data[1])
				pqa.dearmor('\n'.join(copy))

			with pytest.raises(errors.PQAKeyArmorError):
				copy = data.copy()
				line = copy.pop(center)[:-1] + '!'
				copy.insert(center, line)
				pqa.dearmor('\n'.join(copy))

			with pytest.raises(errors.PQAKeyArmorError):
				pqa.dearmor("")

		apk = pqa.armor(public_key).split('\n')
		_reuse_tests(apk)

		ask = pqa.armor(secret_key).split('\n')
		_reuse_tests(ask)

	return closure
