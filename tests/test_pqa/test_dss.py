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
from quantcrypt.internal import errors, constants as const
from quantcrypt.internal.pqa import dss_algos as dss
from quantcrypt.internal.pqa.base_dss import DSSParamSizes, BaseDSS
from .conftest import BaseAlgorithmTester


class TestDssAlgorithms(BaseAlgorithmTester):
	@classmethod
	def test_mldsa_44(cls, alt_tmp_path):
		cls.run_tests(alt_tmp_path, dss.MLDSA_44)

	@classmethod
	def test_mldsa_65(cls, alt_tmp_path):
		cls.run_tests(alt_tmp_path, dss.MLDSA_65)

	@classmethod
	def test_mlds_87(cls, alt_tmp_path):
		cls.run_tests(alt_tmp_path, dss.MLDSA_87)

	@classmethod
	def test_falcon_512(cls, alt_tmp_path):
		cls.run_tests(alt_tmp_path, dss.FALCON_512)

	@classmethod
	def test_falcon_1024(cls, alt_tmp_path):
		cls.run_tests(alt_tmp_path, dss.FALCON_1024)

	@classmethod
	def test_small_sphincs(cls, alt_tmp_path):
		cls.run_tests(alt_tmp_path, dss.SMALL_SPHINCS)

	@classmethod
	def test_fast_sphincs(cls, alt_tmp_path):
		cls.run_tests(alt_tmp_path, dss.FAST_SPHINCS)

	@classmethod
	def run_tests(cls, alt_tmp_path: Path, dss_class: Type[BaseDSS]):
		for dss_instance in cls.get_pqa_instances(dss_class):
			cls.run_attribute_tests(dss_instance)
			cls.run_cryptography_tests(dss_instance)
			cls.run_invalid_inputs_tests(dss_instance)
			cls.run_sign_verify_file_tests(dss_instance, alt_tmp_path)
			cls.run_armor_success_tests(dss_instance)
			cls.run_armor_failure_tests(dss_instance)
			cls.run_dearmor_failure_tests(dss_instance)

	@classmethod
	def run_attribute_tests(cls, dss_instance: BaseDSS):
		cls.notify(dss_instance, "Testing attributes")

		assert hasattr(dss_instance, "spec")
		assert isinstance(dss_instance.spec, const.AlgoSpec)

		assert hasattr(dss_instance, "variant")
		assert isinstance(dss_instance.variant, const.PQAVariant)

		assert hasattr(dss_instance, "param_sizes")
		assert isinstance(dss_instance.param_sizes, DSSParamSizes)

		assert hasattr(dss_instance, "keygen")
		assert isinstance(dss_instance.keygen, Callable)

		assert hasattr(dss_instance, "sign")
		assert isinstance(dss_instance.sign, Callable)

		assert hasattr(dss_instance, "verify")
		assert isinstance(dss_instance.verify, Callable)

		assert hasattr(dss_instance, "armor")
		assert isinstance(dss_instance.armor, Callable)

		assert hasattr(dss_instance, "dearmor")
		assert isinstance(dss_instance.dearmor, Callable)

	@classmethod
	def run_cryptography_tests(cls, dss_instance: BaseDSS):
		cls.notify(dss_instance, "Testing cryptography")

		message = b"Hello World"
		params = dss_instance.param_sizes
		public_key, secret_key = dss_instance.keygen()

		assert isinstance(public_key, bytes)
		assert len(public_key) == params.pk_size
		assert isinstance(secret_key, bytes)
		assert len(secret_key) == params.sk_size

		signature = dss_instance.sign(secret_key, message)
		assert isinstance(signature, bytes)
		assert len(signature) <= params.sig_size
		assert dss_instance.verify(public_key, message, signature, raises=False)

	@classmethod
	def run_invalid_inputs_tests(cls, dss_instance: BaseDSS):
		cls.notify(dss_instance, "Testing invalid inputs")

		message = b"Hello World"
		params = dss_instance.param_sizes
		public_key, secret_key = dss_instance.keygen()

		for isk in cls.invalid_keys(secret_key):
			with pytest.raises(ValidationError):
				dss_instance.sign(isk, message)

		for inv_msg in cls.invalid_messages(message):
			with pytest.raises(ValidationError):
				dss_instance.sign(secret_key, inv_msg)

		signature = dss_instance.sign(secret_key, message)

		for ipk in cls.invalid_keys(public_key):
			with pytest.raises(ValidationError):
				dss_instance.verify(ipk, message, signature)

		for inv_msg in cls.invalid_messages(message):
			with pytest.raises(ValidationError):
				dss_instance.verify(public_key, inv_msg, signature)

		for inv_sig in cls.invalid_signatures(signature, params.sig_size):
			with pytest.raises(ValidationError):
				dss_instance.verify(public_key, message, inv_sig)

		with pytest.raises(errors.DSSVerifyFailedError):
			dss_instance.verify(public_key[::-1], message, signature)

		with pytest.raises(errors.DSSVerifyFailedError):
			dss_instance.verify(public_key, message[::-1], signature)

		with pytest.raises(errors.DSSVerifyFailedError):
			dss_instance.verify(public_key, message, signature[::-1])

	@classmethod
	def run_sign_verify_file_tests(cls, dss_instance: BaseDSS, alt_tmp_path: Path):
		cls.notify(dss_instance, "Testing file signature verification")

		data_file = alt_tmp_path / "test.txt"
		data_file.write_text("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
		public_key, secret_key = dss_instance.keygen()

		counter = []
		def callback():
			counter.append(1)

		ask = dss_instance.armor(secret_key)
		apk = dss_instance.armor(public_key)

		dss_instance.sign_file(ask, data_file, callback)
		assert sum(counter) == 1

		sf = dss_instance.sign_file(ask, data_file)
		assert sum(counter) == 1

		dss_instance.verify_file(apk, data_file, sf.signature, callback)
		assert sum(counter) == 2

		dss_instance.verify_file(apk, data_file, sf.signature)
		assert sum(counter) == 2

		with pytest.raises(FileNotFoundError):
			dss_instance.sign_file(ask, Path("asdfg"))

		with pytest.raises(FileNotFoundError):
			dss_instance.verify_file(apk, Path("asdfg"), sf.signature)
