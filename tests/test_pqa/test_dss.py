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
from pathlib import Path
from typing import Callable, Type
from pydantic import ValidationError
from quantcrypt.internal.pqa.dss import BaseDSS
from quantcrypt.internal.pqa import errors
from quantcrypt.dss import (
	Dilithium, Falcon,
	FastSphincs, SmallSphincs,
	PQAVariant, DSSParamSizes
)


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

		assert hasattr(dss, "armor")
		assert isinstance(dss.armor, Callable)

		assert hasattr(dss, "dearmor")
		assert isinstance(dss.dearmor, Callable)

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

		with pytest.raises(errors.DSSVerifyFailedError):
			dss.verify(public_key[::-1], message, signature)

		with pytest.raises(errors.DSSVerifyFailedError):
			dss.verify(public_key, message[::-1], signature)

		with pytest.raises(errors.DSSVerifyFailedError):
			dss.verify(public_key, message, signature[::-1])

	return closure


@pytest.fixture(name="sign_verify_file_tests", scope="function")
def fixture_sign_verify_file_tests(tmp_path: Path):
	def closure(dss_cls: Type[BaseDSS]):
		dss = dss_cls()
		pk, sk = dss.keygen()

		data_file = tmp_path / "test.txt"
		data_file.write_text("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

		sf = dss.sign_file(sk, data_file)
		dss.verify_file(pk, data_file, sf.signature)

	return closure


@pytest.fixture(name="sign_verify_file_callback_tests", scope="function")
def fixture_sign_verify_file_callback_tests(tmp_path: Path):
	def closure(dss_cls: Type[BaseDSS]):
		dss = dss_cls()
		pk, sk = dss.keygen()

		data_file = tmp_path / "test.txt"
		data_file.write_text("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

		counter = []

		def callback():
			counter.append(1)

		ask = dss.armor(sk)
		apk = dss.armor(pk)

		sf = dss.sign_file(ask, data_file, callback)
		assert sum(counter) == 1

		dss.verify_file(apk, data_file, sf.signature, callback)
		assert sum(counter) == 2

		with pytest.raises(FileNotFoundError):
			dss.sign_file(ask, Path("asdfg"))

		with pytest.raises(FileNotFoundError):
			dss.verify_file(apk, Path("asdfg"), sf.signature)

	return closure


class TestDilithium:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(Dilithium)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(Dilithium)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(Dilithium)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(Dilithium)

	@staticmethod
	def test_5(armoring_success_tests: Callable):
		armoring_success_tests(Dilithium)

	@staticmethod
	def test_6(armor_failure_tests: Callable):
		armor_failure_tests(Dilithium)

	@staticmethod
	def test_7(dearmor_failure_tests: Callable):
		dearmor_failure_tests(Dilithium)

	@staticmethod
	def test_8(sign_verify_file_tests: Callable):
		sign_verify_file_tests(Dilithium)

	@staticmethod
	def test_9(sign_verify_file_callback_tests: Callable):
		sign_verify_file_callback_tests(Dilithium)


class TestFalcon:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(Falcon)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(Falcon)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(Falcon)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(Falcon)

	@staticmethod
	def test_5(armoring_success_tests: Callable):
		armoring_success_tests(Falcon)

	@staticmethod
	def test_6(armor_failure_tests: Callable):
		armor_failure_tests(Falcon)

	@staticmethod
	def test_7(dearmor_failure_tests: Callable):
		dearmor_failure_tests(Falcon)

	@staticmethod
	def test_8(sign_verify_file_tests: Callable):
		sign_verify_file_tests(Falcon)

	@staticmethod
	def test_9(sign_verify_file_callback_tests: Callable):
		sign_verify_file_callback_tests(Falcon)


class TestFastSphincs:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(FastSphincs)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(FastSphincs)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(FastSphincs)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(FastSphincs)

	@staticmethod
	def test_5(armoring_success_tests: Callable):
		armoring_success_tests(FastSphincs)

	@staticmethod
	def test_6(armor_failure_tests: Callable):
		armor_failure_tests(FastSphincs)

	@staticmethod
	def test_7(dearmor_failure_tests: Callable):
		dearmor_failure_tests(FastSphincs)

	@staticmethod
	def test_8(sign_verify_file_tests: Callable):
		sign_verify_file_tests(FastSphincs)

	@staticmethod
	def test_9(sign_verify_file_callback_tests: Callable):
		sign_verify_file_callback_tests(FastSphincs)


class TestSmallSphincs:
	@staticmethod
	def test_1(pqc_variant_tests: Callable):
		pqc_variant_tests(SmallSphincs)

	@staticmethod
	def test_2(attribute_tests: Callable):
		attribute_tests(SmallSphincs)

	@staticmethod
	def test_3(cryptography_tests: Callable):
		cryptography_tests(SmallSphincs)

	@staticmethod
	def test_4(invalid_inputs_tests: Callable):
		invalid_inputs_tests(SmallSphincs)

	@staticmethod
	def test_5(armoring_success_tests: Callable):
		armoring_success_tests(SmallSphincs)

	@staticmethod
	def test_6(armor_failure_tests: Callable):
		armor_failure_tests(SmallSphincs)

	@staticmethod
	def test_7(dearmor_failure_tests: Callable):
		dearmor_failure_tests(SmallSphincs)

	@staticmethod
	def test_8(sign_verify_file_tests: Callable):
		sign_verify_file_tests(SmallSphincs)

	@staticmethod
	def test_9(sign_verify_file_callback_tests: Callable):
		sign_verify_file_callback_tests(SmallSphincs)
