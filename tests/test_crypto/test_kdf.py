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
from pydantic import ValidationError
from quantcrypt.utils import Argon2Params
from quantcrypt.errors import *
from quantcrypt import KDF


@pytest.fixture(name="good_pw", scope="module")
def fixture_good_pw() -> str:
	return "A8c7hBBTnVC90kP5AIe2"


def test_argon2params_values():
	Argon2Params(
		parallelism=1,
		memory_cost=2**10,
		time_cost=1,
		hash_len=32,
		salt_len=32
	)

	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=0,  # less than 1
			memory_cost=2**10,
			time_cost=1,
			hash_len=32,
			salt_len=32
		)
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**9,  # less than 2**10
			time_cost=1,
			hash_len=32,
			salt_len=32
		)
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=3**10,  # not power of 2
			time_cost=1,
			hash_len=32,
			salt_len=32
		)
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**10,
			time_cost=0,  # less than 1
			hash_len=32,
			salt_len=32
		)
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**10,
			time_cost=1,
			hash_len=31,  # less than 32
			salt_len=32
		)
	with pytest.raises(ValidationError):
		Argon2Params(
			parallelism=1,
			memory_cost=2**10,
			time_cost=1,
			hash_len=32,
			salt_len=31  # less than 32
		)


def test_argon2hash_success(good_pw: str):
	kdf1 = KDF.Argon2Hash(good_pw, testing=True)
	assert kdf1.rehashed is False
	assert kdf1.verified is False

	kdf2 = KDF.Argon2Hash(good_pw, kdf1.public_hash, testing=True)
	assert kdf2.rehashed is False
	assert kdf2.verified is True


def test_argon2hash_errors(good_pw: str):
	kdf = KDF.Argon2Hash(good_pw, testing=True)

	with pytest.raises(KDFVerificationError):
		KDF.Argon2Hash(good_pw[::-1], kdf.public_hash, testing=True)

	with pytest.raises(KDFInvalidHashError):
		KDF.Argon2Hash(good_pw, kdf.public_hash[::-1], testing=True)

	with pytest.raises(KDFWeakPasswordError):
		KDF.Argon2Hash('a' * 7, testing=True)


def test_argon2hash_overrides(good_pw: str):
	ovr_s = Argon2Params(
		parallelism=8,
		memory_cost=2 ** 10,  # smaller than ovr2
		time_cost=6,
		hash_len=32,
		salt_len=32
	)
	ovr_ref = Argon2Params(
		parallelism=8,
		memory_cost=2**11,  # Reference
		time_cost=6,
		hash_len=32,
		salt_len=32
	)
	ovr_l = Argon2Params(
		parallelism=8,
		memory_cost=2**12,  # larger than ovr2
		time_cost=6,
		hash_len=32,
		salt_len=32
	)
	kdf_ref = KDF.Argon2Hash(good_pw, params=ovr_ref)

	kdf_s = KDF.Argon2Hash(good_pw, kdf_ref.public_hash, params=ovr_s)
	assert kdf_s.rehashed is True
	assert kdf_s.verified is True

	kdf_l = KDF.Argon2Hash(good_pw, kdf_ref.public_hash, params=ovr_l)
	assert kdf_l.rehashed is True
	assert kdf_l.verified is True


def test_argon2hash_duration(good_pw: str):
	def test():
		KDF.Argon2Hash(good_pw)

	assert timeit.timeit(test, number=1) > 0.4


def test_argon2secret_success(good_pw: str):
	kdf1 = KDF.Argon2Secret(good_pw, testing=True)

	assert isinstance(kdf1.public_salt, str)
	assert isinstance(kdf1.secret_key, bytes)

	kdf2 = KDF.Argon2Secret(good_pw, kdf1.public_salt, testing=True)
	assert kdf2.secret_key == kdf1.secret_key


def test_argon2secret_errors(good_pw: str):
	with pytest.raises(KDFWeakPasswordError):
		KDF.Argon2Secret('a' * 7, testing=True)


def test_argon2secret_overrides(good_pw: str):
	ovr1 = Argon2Params(
		parallelism=4,
		memory_cost=2**12,
		time_cost=2,
		hash_len=64,
		salt_len=48
	)
	kdf = KDF.Argon2Secret(good_pw, params=ovr1)
	assert kdf.params == ovr1


def test_argon2secret_duration(good_pw: str):
	def test():
		KDF.Argon2Secret(good_pw)

	assert timeit.timeit(test, number=1) > 2.9
