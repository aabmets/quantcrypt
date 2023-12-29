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
from quantcrypt.errors import *
from quantcrypt import KDF


@pytest.fixture(name="good_pw", scope="module")
def fixture_good_pw() -> str:
	return "A8c7hBBTnVC90kP5AIe2"


def test_argon2_web_success(good_pw: str):
	kdf1 = KDF.Argon2Web(good_pw, testing=True)
	assert kdf1.rehashed is False
	assert kdf1.verified is False

	kdf2 = KDF.Argon2Web(good_pw, kdf1.public_hash, testing=True)
	assert kdf2.rehashed is False
	assert kdf2.verified is True


def test_argon2_web_errors(good_pw: str):
	kdf = KDF.Argon2Web(good_pw, testing=True)

	with pytest.raises(KDFVerificationError):
		KDF.Argon2Web(good_pw[::-1], kdf.public_hash, testing=True)

	with pytest.raises(KDFInvalidHashError):
		KDF.Argon2Web(good_pw, kdf.public_hash[::-1], testing=True)

	with pytest.raises(KDFWeakPasswordError):
		KDF.Argon2Web('a' * 7, testing=True)


def test_argon2_file_success(good_pw: str):
	kdf1 = KDF.Argon2File(good_pw, testing=True)

	assert isinstance(kdf1.public_salt, str)
	assert isinstance(kdf1.secret_hash, bytes)

	kdf2 = KDF.Argon2File(good_pw, kdf1.public_salt, testing=True)
	assert kdf2.secret_hash == kdf1.secret_hash


def test_argon2_file_errors(good_pw: str):
	with pytest.raises(KDFWeakPasswordError):
		KDF.Argon2File('a' * 7, testing=True)


def test_argon2_web_real_time(good_pw: str):
	def test():
		KDF.Argon2Web(good_pw)

	assert timeit.timeit(test, number=1) > 0.4


def test_argon2_file_real_time(good_pw: str):
	def test():
		KDF.Argon2File(good_pw)

	assert timeit.timeit(test, number=1) > 2.9
