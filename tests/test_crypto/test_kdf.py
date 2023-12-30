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
import timeit
import pytest
from typing import Type, Callable
from pydantic import ValidationError
from quantcrypt.utils import Argon2Params
from quantcrypt.errors import *
from quantcrypt import KDF


@pytest.fixture(name="good_pw", scope="module")
def fixture_good_pw() -> str:
	return "A8c7hBBTnVC90kP5AIe2"


@pytest.fixture(name="test_context", scope="module")
def fixture_test_context() -> Callable:
	def closure(kdf_cls: Type, *_, **__):
		class Context:
			def __enter__(self):
				setattr(kdf_cls, "_testing", True)

			def __exit__(self, exc_type, exc_value, traceback):
				setattr(kdf_cls, "_testing", False)

		return Context()
	return closure


def test_argon2params_good_values():
	Argon2Params(
		memory_cost=2**15,
		parallelism=1,
		time_cost=1,
		hash_len=64,
		salt_len=16
	)


def test_argon2params_bad_parallelism():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=0,  # less than 1
			memory_cost=2**15,
			time_cost=1,
			hash_len=64,
			salt_len=16
		)


def test_argon2params_too_weak_mem_cost():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**14,  # less than 2**15
			time_cost=1,
			hash_len=64,
			salt_len=16
		)


def test_argon2params_bad_mem_cost_number():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=3**15,  # not power of 2
			time_cost=1,
			hash_len=64,
			salt_len=16
		)


def test_argon2params_bad_time_cost():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**15,
			time_cost=0,  # less than 1
			hash_len=64,
			salt_len=16
		)


def test_argon2params_too_short_hash_len():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**15,
			time_cost=1,
			hash_len=15,  # less than 16
			salt_len=16
		)


def test_argon2params_too_long_hash_len():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**15,
			time_cost=1,
			hash_len=65,  # more than 64
			salt_len=16
		)


def test_argon2params_too_short_salt_len():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**15,
			time_cost=1,
			hash_len=64,
			salt_len=15  # less than 16
		)


def test_argon2params_too_long_salt_len():
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**15,
			time_cost=1,
			hash_len=64,
			salt_len=65  # more than 64
		)


def test_argon2_success(good_pw: str, test_context: Callable):
	with test_context(KDF.Argon2):
		kdf1 = KDF.Argon2(good_pw)
		assert kdf1.rehashed is False
		assert kdf1.verified is False

		kdf2 = KDF.Argon2(good_pw, kdf1.public_hash)
		assert kdf2.rehashed is False
		assert kdf2.verified is True


def test_argon2_errors(good_pw: str, test_context: Callable):
	with test_context(KDF.Argon2):
		kdf = KDF.Argon2(good_pw)

		with pytest.raises(KDFVerificationError):
			KDF.Argon2(good_pw[::-1], kdf.public_hash)

		with pytest.raises(KDFInvalidHashError):
			KDF.Argon2(good_pw, kdf.public_hash[::-1])

		with pytest.raises(KDFWeakPasswordError):
			KDF.Argon2('a' * 7)


def test_argon2_overrides(good_pw: str):
	ovr_s = Argon2Params(
		parallelism=8,
		memory_cost=2 ** 15,  # smaller than ovr2
		time_cost=1,
		hash_len=16,
		salt_len=16
	)
	ovr_ref = Argon2Params(
		parallelism=8,
		memory_cost=2**16,  # Reference
		time_cost=1,
		hash_len=16,
		salt_len=16
	)
	ovr_l = Argon2Params(
		parallelism=8,
		memory_cost=2**17,  # larger than ovr2
		time_cost=1,
		hash_len=16,
		salt_len=16
	)
	kdf_ref = KDF.Argon2(good_pw, params=ovr_ref)

	kdf_s = KDF.Argon2(good_pw, kdf_ref.public_hash, params=ovr_s)
	assert kdf_s.rehashed is True
	assert kdf_s.verified is True

	kdf_l = KDF.Argon2(good_pw, kdf_ref.public_hash, params=ovr_l)
	assert kdf_l.rehashed is True
	assert kdf_l.verified is True


def test_argon2_duration(good_pw: str):
	def test():
		KDF.Argon2(good_pw)

	assert timeit.timeit(test, number=1) > 0.4


def test_argon2key_success(good_pw: str, test_context: Callable):
	with test_context(KDF.Argon2Key):
		kdf1 = KDF.Argon2Key(good_pw)

		assert isinstance(kdf1.public_salt, str)
		assert isinstance(kdf1.secret_key, bytes)

		kdf2 = KDF.Argon2Key(good_pw, kdf1.public_salt)
		assert kdf2.secret_key == kdf1.secret_key


def test_argon2key_errors(good_pw: str, test_context: Callable):
	with test_context(KDF.Argon2Key):
		with pytest.raises(KDFWeakPasswordError):
			KDF.Argon2Key('a' * 7)


def test_argon2key_overrides(good_pw: str):
	ovr1 = Argon2Params(
		parallelism=4,
		memory_cost=2**15,
		time_cost=1,
		hash_len=20,
		salt_len=20
	)
	kdf = KDF.Argon2Key(good_pw, params=ovr1)
	assert kdf.params == ovr1


def test_argon2secret_duration(good_pw: str):
	def test():
		KDF.Argon2Key(good_pw)

	assert timeit.timeit(test, number=1) > 2.5
