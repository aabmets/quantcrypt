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
from secrets import compare_digest
from typing import Callable
from quantcrypt import KEM
from quantcrypt.utils import *


def test_kyber_attributes():
	kem = KEM.Kyber()

	assert hasattr(kem, "variant")
	assert isinstance(kem.variant, Variant)

	assert hasattr(kem, "params")
	assert isinstance(kem.params, KemByteParams)

	assert hasattr(kem, "keygen")
	assert isinstance(kem.keygen, Callable)

	assert hasattr(kem, "encaps")
	assert isinstance(kem.encaps, Callable)

	assert hasattr(kem, "decaps")
	assert isinstance(kem.decaps, Callable)

	assert hasattr(kem, "name")
	assert isinstance(kem.name, str)


def test_kyber_cryptography():
	kem = KEM.Kyber()

	public_key, secret_key = kem.keygen()
	cipher_text, shared_secret = kem.encaps(public_key)
	identical_shared_secret = kem.decaps(secret_key, cipher_text)

	assert compare_digest(shared_secret, identical_shared_secret), \
		"Kyber decaps did not produce identical shared secret"
