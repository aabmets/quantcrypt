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
from pydantic import ValidationError
from quantcrypt.internal.crypto.dss import BaseDSS
from quantcrypt.utils import *
from quantcrypt.errors import *
from quantcrypt import DSS


@pytest.fixture(name="attribute_tests", scope="module")
def fixture_attribute_tests():
	def closure(dss_cls: Type[BaseDSS]):
		dss = dss_cls()

		assert hasattr(dss, "name")
		assert isinstance(dss.name, str)

		assert hasattr(dss, "variant")
		assert isinstance(dss.variant, PQAVariant)

		assert hasattr(dss, "param_sizes")
		assert isinstance(dss.param_sizes, DSSParamSizes)

		assert hasattr(dss, "keygen")
		assert isinstance(dss.keygen, Callable)

		assert hasattr(dss, "sign")
		assert isinstance(dss.sign, Callable)

		assert hasattr(dss, "verify")
		assert isinstance(dss.verify, Callable)

	return closure


@pytest.fixture(name="cryptography_tests", scope="module")
def fixture_cryptography_tests():
	def closure(dss_cls: Type[BaseDSS]):
		dss = dss_cls()
		params = dss.param_sizes
		message = b"Hello World"

		public_key, secret_key = dss.keygen()

		assert isinstance(public_key, bytes)
		assert len(public_key) == params.pk_size
		assert isinstance(secret_key, bytes)
		assert len(secret_key) == params.sk_size

		signature = dss.sign(secret_key, message)

		assert isinstance(signature, bytes)
		assert len(signature) <= params.sig_size
		assert dss.verify(public_key, message, signature, raises=False)

	return closure


@pytest.fixture(name="invalid_inputs_tests", scope="module")
def fixture_invalid_inputs_tests(
		invalid_keys: Callable,
		invalid_messages: Callable,
		invalid_signatures: Callable):
	def closure(dss_cls: Type[BaseDSS]):
		dss = dss_cls()
		params = dss.param_sizes
		message = b"Hello World"

		public_key, secret_key = dss.keygen()

		for isk in invalid_keys(secret_key):
			with pytest.raises(ValidationError):
				dss.sign(isk, message)

		for inv_msg in invalid_messages(message):
			with pytest.raises(ValidationError):
				dss.sign(secret_key, inv_msg)

		signature = dss.sign(secret_key, message)

		for ipk in invalid_keys(public_key):
			with pytest.raises(ValidationError):
				dss.verify(ipk, message, signature)

		for inv_msg in invalid_messages(message):
			with pytest.raises(ValidationError):
				dss.verify(public_key, inv_msg, signature)

		for inv_sig in invalid_signatures(signature, params.sig_size):
			with pytest.raises(ValidationError):
				dss.verify(public_key, message, inv_sig)

		with pytest.raises(DSSVerifyFailedError):
			dss.verify(public_key[::-1], message, signature)

		with pytest.raises(DSSVerifyFailedError):
			dss.verify(public_key, message[::-1], signature)

		with pytest.raises(DSSVerifyFailedError):
			dss.verify(public_key, message, signature[::-1])

	return closure


class TestDilithium:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(DSS.Dilithium)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(DSS.Dilithium)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(DSS.Dilithium)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(DSS.Dilithium)


class TestFalcon:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(DSS.Falcon)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(DSS.Falcon)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(DSS.Falcon)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(DSS.Falcon)


class TestFastSphincs:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(DSS.FastSphincs)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(DSS.FastSphincs)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(DSS.FastSphincs)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(DSS.FastSphincs)


class TestSmallSphincs:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(DSS.SmallSphincs)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(DSS.SmallSphincs)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(DSS.SmallSphincs)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(DSS.SmallSphincs)