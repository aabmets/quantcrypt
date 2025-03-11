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
from secrets import compare_digest
from pydantic import ValidationError
from quantcrypt.internal.pqa.base_kem import BaseKEM
from quantcrypt.internal import constants as const
from quantcrypt.kem import (
	MLKEM_512, MLKEM_768, MLKEM_1024,
	KEMParamSizes
)


@pytest.fixture(name="attribute_tests", scope="module")
def fixture_attribute_tests():
	def closure(kem_cls: Type[BaseKEM]):
		kem = kem_cls()

		assert hasattr(kem, "spec")
		assert isinstance(kem.spec, const.AlgoSpec)

		assert hasattr(kem, "variant")
		assert isinstance(kem.variant, const.PQAVariant)

		assert hasattr(kem, "param_sizes")
		assert isinstance(kem.param_sizes, KEMParamSizes)

		assert hasattr(kem, "keygen")
		assert isinstance(kem.keygen, Callable)

		assert hasattr(kem, "encaps")
		assert isinstance(kem.encaps, Callable)

		assert hasattr(kem, "decaps")
		assert isinstance(kem.decaps, Callable)

		assert hasattr(kem, "armor")
		assert isinstance(kem.armor, Callable)

		assert hasattr(kem, "dearmor")
		assert isinstance(kem.dearmor, Callable)

	return closure


@pytest.fixture(name="cryptography_tests", scope="module")
def fixture_cryptography_tests():
	def closure(kem_cls: Type[BaseKEM]):
		kem = kem_cls()

		params = kem.param_sizes
		public_key, secret_key = kem.keygen()

		assert isinstance(public_key, bytes)
		assert len(public_key) == params.pk_size
		assert isinstance(secret_key, bytes)
		assert len(secret_key) == params.sk_size

		cipher_text, shared_secret = kem.encaps(public_key)

		assert isinstance(cipher_text, bytes)
		assert len(cipher_text) == params.ct_size
		assert isinstance(shared_secret, bytes)
		assert len(shared_secret) == params.ss_size

		decaps_shared_secret = kem.decaps(secret_key, cipher_text)

		assert isinstance(decaps_shared_secret, bytes)
		assert len(decaps_shared_secret) == params.ss_size
		assert compare_digest(shared_secret, decaps_shared_secret)

	return closure


@pytest.fixture(name="invalid_inputs_tests", scope="module")
def fixture_invalid_inputs_tests(
		invalid_keys: Callable,
		invalid_ciphertexts: Callable):

	def closure(kem_cls: Type[BaseKEM]):
		kem = kem_cls()
		public_key, secret_key = kem.keygen()

		for ipk in invalid_keys(public_key):
			with pytest.raises(ValidationError):
				kem.encaps(ipk)

		cipher_text, _ = kem.encaps(public_key)

		for isk in invalid_keys(secret_key):
			with pytest.raises(ValidationError):
				kem.decaps(isk, cipher_text)

		for ict in invalid_ciphertexts(cipher_text):
			with pytest.raises(ValidationError):
				kem.decaps(secret_key, ict)

	return closure


class Test_KEM_Algorithms:
	algos = [MLKEM_512, MLKEM_768, MLKEM_1024]

	@classmethod
	def test_1(cls, pqc_variant_tests: Callable):
		for algo in cls.algos:
			pqc_variant_tests(algo)

	@classmethod
	def test_2(cls, attribute_tests: Callable):
		for algo in cls.algos:
			attribute_tests(algo)

	@classmethod
	def test_3(cls, cryptography_tests: Callable):
		for algo in cls.algos:
			cryptography_tests(algo)

	@classmethod
	def test_4(cls, invalid_inputs_tests: Callable):
		for algo in cls.algos:
			invalid_inputs_tests(algo)

	@classmethod
	def test_5(cls, armoring_success_tests: Callable):
		for algo in cls.algos:
			armoring_success_tests(algo)

	@classmethod
	def test_6(cls, armor_failure_tests: Callable):
		for algo in cls.algos:
			armor_failure_tests(algo)

	@classmethod
	def test_7(cls, dearmor_failure_tests: Callable):
		for algo in cls.algos:
			dearmor_failure_tests(algo)
