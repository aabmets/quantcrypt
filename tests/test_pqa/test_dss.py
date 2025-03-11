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
from quantcrypt.internal.pqa.base_dss import BaseDSS
from quantcrypt.internal import constants as const
from quantcrypt.internal import errors
from quantcrypt.dss import (
	MLDSA_44, MLDSA_65, MLDSA_87,
	FALCON_512, FALCON_1024,
	FAST_SPHINCS, SMALL_SPHINCS,
	DSSParamSizes
)


@pytest.fixture(name="attribute_tests", scope="module")
def fixture_attribute_tests():
	def closure(dss_cls: Type[BaseDSS]):
		dss = dss_cls()

		assert hasattr(dss, "spec")
		assert isinstance(dss.spec, const.AlgoSpec)

		assert hasattr(dss, "variant")
		assert isinstance(dss.variant, const.PQAVariant)

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


class Test_DSS_Algorithms:
	algos = [
		MLDSA_44,
		MLDSA_65,
		MLDSA_87,
		FALCON_512,
		FALCON_1024,
		SMALL_SPHINCS,
		FAST_SPHINCS
	]

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

	@classmethod
	def test_8(cls, sign_verify_file_tests: Callable):
		for algo in cls.algos:
			sign_verify_file_tests(algo)

	@classmethod
	def test_9(cls, sign_verify_file_callback_tests: Callable):
		for algo in cls.algos:
			sign_verify_file_callback_tests(algo)
