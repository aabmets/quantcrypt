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
from quantcrypt.kdf import Argon2
from quantcrypt.utils import KDFParams, MemCost
from quantcrypt.internal.kdf import errors
from quantcrypt.internal import utils


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
	KDFParams(
		memory_cost=MemCost.MB(32),
		parallelism=1,
		time_cost=1,
		hash_len=64,
		salt_len=16
	)


def test_argon2params_bad_parallelism():
	with pytest.raises(ValidationError):
		KDFParams(
			memory_cost=MemCost.MB(32),
			parallelism=0,  # less than 1
			time_cost=1,
			hash_len=64,
			salt_len=16
		)


def test_argon2params_bad_time_cost():
	with pytest.raises(ValidationError):
		KDFParams(
			memory_cost=MemCost.MB(32),
			parallelism=1,
			time_cost=0,  # less than 1
			hash_len=64,
			salt_len=16
		)


def test_argon2params_too_short_hash_len():
	with pytest.raises(ValidationError):
		KDFParams(
			memory_cost=MemCost.MB(32),
			parallelism=1,
			time_cost=1,
			hash_len=15,  # less than 16
			salt_len=16
		)


def test_argon2params_too_long_hash_len():
	with pytest.raises(ValidationError):
		KDFParams(
			memory_cost=MemCost.MB(32),
			parallelism=1,
			time_cost=1,
			hash_len=65,  # more than 64
			salt_len=16
		)


def test_argon2params_too_short_salt_len():
	with pytest.raises(ValidationError):
		KDFParams(
			memory_cost=MemCost.MB(32),
			parallelism=1,
			time_cost=1,
			hash_len=64,
			salt_len=15  # less than 16
		)


def test_argon2params_too_long_salt_len():
	with pytest.raises(ValidationError):
		KDFParams(
			memory_cost=MemCost.MB(32),
			parallelism=1,
			time_cost=1,
			hash_len=64,
			salt_len=65  # more than 64
		)


def test_argon2hash_success(good_pw: str, test_context: Callable):
	with test_context(Argon2.Hash):
		kdf1 = Argon2.Hash(good_pw)
		assert kdf1.rehashed is False
		assert kdf1.verified is False

		kdf2 = Argon2.Hash(good_pw, kdf1.public_hash)
		assert kdf2.rehashed is False
		assert kdf2.verified is True


def test_argon2hash_errors(good_pw: str, test_context: Callable):
	with test_context(Argon2.Hash):
		kdf = Argon2.Hash(good_pw)

		with pytest.raises(errors.KDFVerificationError):
			Argon2.Hash(good_pw[::-1], kdf.public_hash)

		with pytest.raises(errors.KDFInvalidHashError):
			Argon2.Hash(good_pw, kdf.public_hash[::-1])

		with pytest.raises(errors.KDFWeakPasswordError):
			Argon2.Hash('a' * 7)


def test_argon2hash_overrides(good_pw: str):
	ovr_s = KDFParams(
		memory_cost=MemCost.MB(32),  # smaller than ovr2
		parallelism=8,
		time_cost=1,
		hash_len=16,
		salt_len=16
	)
	ovr_ref = KDFParams(
		memory_cost=MemCost.MB(64),  # Reference
		parallelism=8,
		time_cost=1,
		hash_len=16,
		salt_len=16
	)
	ovr_l = KDFParams(
		memory_cost=MemCost.MB(128),  # larger than ovr2
		parallelism=8,
		time_cost=1,
		hash_len=16,
		salt_len=16
	)
	kdf_ref = Argon2.Hash(good_pw, params=ovr_ref)

	kdf_s = Argon2.Hash(good_pw, kdf_ref.public_hash, params=ovr_s)
	assert kdf_s.rehashed is True
	assert kdf_s.verified is True

	kdf_l = Argon2.Hash(good_pw, kdf_ref.public_hash, params=ovr_l)
	assert kdf_l.rehashed is True
	assert kdf_l.verified is True


def test_argon2hash_duration(good_pw: str):
	def test():
		Argon2.Hash(good_pw)

	assert timeit.timeit(test, number=1) > 0.35


def test_argon2key_success(good_pw: str, test_context: Callable):
	with test_context(Argon2.Key):
		kdf1 = Argon2.Key(good_pw)

		assert isinstance(kdf1.public_salt, str)
		assert isinstance(kdf1.secret_key, bytes)

		kdf2 = Argon2.Key(good_pw, kdf1.public_salt)
		assert kdf2.secret_key == kdf1.secret_key

		kdf3 = Argon2.Key(good_pw, utils.b64(kdf1.public_salt))
		assert kdf3.secret_key == kdf1.secret_key


def test_argon2key_custom_hash_length():
	kdf = Argon2.Key(b'anything', params=KDFParams(
		memory_cost=MemCost.MB(32), time_cost=1, parallelism=1, hash_len=30
	))
	assert len(kdf.secret_key) == 30


def test_argon2key_errors(good_pw: str, test_context: Callable):
	with test_context(Argon2.Key):
		with pytest.raises(errors.KDFWeakPasswordError):
			Argon2.Key('a' * 7)


def test_argon2key_overrides(good_pw: str):
	ovr1 = KDFParams(
		memory_cost=MemCost.MB(32),
		parallelism=4,
		time_cost=1,
		hash_len=20,
		salt_len=20
	)
	kdf = Argon2.Key(good_pw, params=ovr1)
	assert kdf.params == ovr1


def test_argon2key_duration(good_pw: str):
	def test():
		Argon2.Key(good_pw)

	assert timeit.timeit(test, number=1) > 3.5
