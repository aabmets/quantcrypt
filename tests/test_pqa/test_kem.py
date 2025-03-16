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
from secrets import compare_digest
from pydantic import ValidationError
from quantcrypt.internal import constants as const
from quantcrypt.internal.pqa import kem_algos as kem
from quantcrypt.kem import KEMParamSizes, BaseKEM
from .conftest import BaseAlgorithmTester


class TestKemAlgorithms(BaseAlgorithmTester):
	@classmethod
	def test_mlkem_512(cls):
		cls.run_tests(Path(), kem.MLKEM_512)

	@classmethod
	def test_mlkem_768(cls):
		cls.run_tests(Path(), kem.MLKEM_768)

	@classmethod
	def test_mlkem_1024(cls):
		cls.run_tests(Path(), kem.MLKEM_1024)

	@classmethod
	def run_tests(cls, alt_tmp_path, kem_class: Type[BaseKEM]):
		for kem_instance in cls.get_pqa_instances(kem_class):
			cls.run_attribute_tests(kem_instance)
			cls.run_cryptography_tests(kem_instance)
			cls.run_invalid_inputs_tests(kem_instance)
			cls.run_armor_success_tests(kem_instance)
			cls.run_armor_failure_tests(kem_instance)
			cls.run_dearmor_failure_tests(kem_instance)

	@classmethod
	def run_attribute_tests(cls, kem_instance: BaseKEM):
		cls.notify(kem_instance, "Testing attributes")

		assert hasattr(kem_instance, "spec")
		assert isinstance(kem_instance.spec, const.AlgoSpec)

		assert hasattr(kem_instance, "variant")
		assert isinstance(kem_instance.variant, const.PQAVariant)

		assert hasattr(kem_instance, "param_sizes")
		assert isinstance(kem_instance.param_sizes, KEMParamSizes)

		assert hasattr(kem_instance, "keygen")
		assert isinstance(kem_instance.keygen, Callable)

		assert hasattr(kem_instance, "encaps")
		assert isinstance(kem_instance.encaps, Callable)

		assert hasattr(kem_instance, "decaps")
		assert isinstance(kem_instance.decaps, Callable)

		assert hasattr(kem_instance, "armor")
		assert isinstance(kem_instance.armor, Callable)

		assert hasattr(kem_instance, "dearmor")
		assert isinstance(kem_instance.dearmor, Callable)

	@classmethod
	def run_cryptography_tests(cls, kem_instance: BaseKEM):
		cls.notify(kem_instance, "Testing cryptography")

		params = kem_instance.param_sizes
		public_key, secret_key = kem_instance.keygen()

		assert isinstance(public_key, bytes)
		assert len(public_key) == params.pk_size
		assert isinstance(secret_key, bytes)
		assert len(secret_key) == params.sk_size

		cipher_text, shared_secret = kem_instance.encaps(public_key)
		assert isinstance(cipher_text, bytes)
		assert len(cipher_text) == params.ct_size
		assert isinstance(shared_secret, bytes)
		assert len(shared_secret) == params.ss_size

		decaps_shared_secret = kem_instance.decaps(secret_key, cipher_text)
		assert isinstance(decaps_shared_secret, bytes)
		assert len(decaps_shared_secret) == params.ss_size
		assert compare_digest(shared_secret, decaps_shared_secret)

	@classmethod
	def run_invalid_inputs_tests(cls, kem_instance: BaseKEM):
		cls.notify(kem_instance, "Testing invalid inputs")

		public_key, secret_key = kem_instance.keygen()
		cipher_text, _ = kem_instance.encaps(public_key)

		for ipk in cls.invalid_keys(public_key):
			with pytest.raises(ValidationError):
				kem_instance.encaps(ipk)

		for isk in cls.invalid_keys(secret_key):
			with pytest.raises(ValidationError):
				kem_instance.decaps(isk, cipher_text)

		for ict in cls.invalid_ciphertexts(cipher_text):
			with pytest.raises(ValidationError):
				kem_instance.decaps(secret_key, ict)
