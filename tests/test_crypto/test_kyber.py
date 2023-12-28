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
from typing import Callable
from secrets import compare_digest
from pydantic import ValidationError
from quantcrypt.typedefs import *
from quantcrypt import KEM


def test_kyber_attributes():
	kem = KEM.Kyber()

	assert hasattr(kem, "name")
	assert isinstance(kem.name, str)

	assert hasattr(kem, "variant")
	assert isinstance(kem.variant, Variant)

	assert hasattr(kem, "param_sizes")
	assert isinstance(kem.param_sizes, KemParamSizes)

	assert hasattr(kem, "keygen")
	assert isinstance(kem.keygen, Callable)

	assert hasattr(kem, "encaps")
	assert isinstance(kem.encaps, Callable)

	assert hasattr(kem, "decaps")
	assert isinstance(kem.decaps, Callable)


def test_kyber_variants():
	kem = KEM.Kyber()
	assert kem.variant == Variant.CLEAN

	kem = KEM.Kyber(Variant.CLEAN)
	assert kem.variant == Variant.CLEAN

	with pytest.raises(ModuleNotFoundError):
		KEM.Kyber(Variant.AVX2)


def test_kyber_cryptography():
	kem = KEM.Kyber()
	params = kem.param_sizes
	public_key, secret_key = kem.keygen()

	assert isinstance(public_key, bytes)
	assert len(public_key) == params.pk_size
	assert isinstance(secret_key, bytes)
	assert len(secret_key) == params.sk_size

	cipher_text, shared_secret = kem.encaps(public_key)

	assert isinstance(cipher_text, bytes)
	assert len(cipher_text) == params.ct_size
	assert isinstance(shared_secret, bytes)
	assert len(shared_secret) == params.ss_size

	decaps_shared_secret = kem.decaps(secret_key, cipher_text)

	assert isinstance(decaps_shared_secret, bytes)
	assert len(decaps_shared_secret) == params.ss_size
	assert compare_digest(shared_secret, decaps_shared_secret)


def test_kyber_invalid_inputs(
		invalid_keys: Callable,
		invalid_ciphertexts: Callable):

	kem = KEM.Kyber()
	public_key, secret_key = kem.keygen()

	for ipk in invalid_keys(public_key):
		with pytest.raises(ValidationError):
			kem.encaps(ipk)

	cipher_text, shared_secret = kem.encaps(public_key)

	for isk in invalid_keys(secret_key):
		with pytest.raises(ValidationError):
			kem.decaps(isk, cipher_text)

	for ict in invalid_ciphertexts(cipher_text):
		with pytest.raises(ValidationError):
			kem.decaps(secret_key, ict)
