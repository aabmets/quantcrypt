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
from secrets import compare_digest
from pydantic import ValidationError
from typing import Callable, Type, cast
from quantcrypt.internal.crypto.kem import BaseKEM
from quantcrypt.errors import PQAInvalidInputError
from quantcrypt.utils import *
from quantcrypt import KEM


@pytest.fixture(name="attribute_tests", scope="module")
def fixture_attribute_tests():
	def closure(kem_cls: Type[BaseKEM]):
		kem = kem_cls()

		assert hasattr(kem, "name")
		assert isinstance(kem.name, str)

		assert hasattr(kem, "variant")
		assert isinstance(kem.variant, PQAVariant)

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

		cipher_text, shared_secret = kem.encaps(public_key)

		for isk in invalid_keys(secret_key):
			with pytest.raises(ValidationError):
				kem.decaps(isk, cipher_text)

		for ict in invalid_ciphertexts(cipher_text):
			with pytest.raises(ValidationError):
				kem.decaps(secret_key, ict)

	return closure


@pytest.fixture(name="armoring_success_tests", scope="module")
def fixture_armoring_tests():
	def closure(kem_cls: Type[BaseKEM]):
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


@pytest.fixture(name="armor_failure_tests", scope="module")
def fixture_armoring_failure_tests():
	def closure(kem_cls: Type[BaseKEM]):
		kem = kem_cls()
		public_key, secret_key = kem.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				kem.armor(cast(key(), bytes))

		for key in [public_key + b'x', public_key[:-1]]:
			with pytest.raises(PQAInvalidInputError):
				kem.armor(key)

		for key in [secret_key + b'x', secret_key[:-1]]:
			with pytest.raises(PQAInvalidInputError):
				kem.armor(key)

	return closure


@pytest.fixture(name="dearmor_failure_tests", scope="module")
def fixture_dearmoring_failure_tests():
	def closure(kem_cls: Type[BaseKEM]):
		kem = kem_cls()
		public_key, secret_key = kem.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				kem.dearmor(cast(key(), bytes))

		def _reuse_tests(data: list[str]):
			center = len(data) // 2

			with pytest.raises(PQAInvalidInputError):
				copy = data.copy()
				copy.pop(center)
				kem.dearmor('\n'.join(copy))

			with pytest.raises(PQAInvalidInputError):
				copy = data.copy()
				copy.insert(center, 'abcd')
				kem.dearmor('\n'.join(copy))

			with pytest.raises(PQAInvalidInputError):
				copy = data.copy()
				line = copy.pop(center)[:-1] + '!'
				copy.insert(center, line)
				kem.dearmor('\n'.join(copy))

		apk = kem.armor(public_key).split('\n')
		_reuse_tests(apk)

		ask = kem.armor(secret_key).split('\n')
		_reuse_tests(ask)

	return closure


class TestKyber:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(KEM.Kyber)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(KEM.Kyber)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(KEM.Kyber)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(KEM.Kyber)

	@staticmethod
	def test_5(armoring_success_tests: Callable):
		armoring_success_tests(KEM.Kyber)

	@staticmethod
	def test_6(armor_failure_tests: Callable):
		armor_failure_tests(KEM.Kyber)

	@staticmethod
	def test_7(dearmor_failure_tests: Callable):
		dearmor_failure_tests(KEM.Kyber)
