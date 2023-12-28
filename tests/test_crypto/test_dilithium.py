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
from pydantic import ValidationError
from quantcrypt.typedefs import *
from quantcrypt.errors import *
from quantcrypt import DSS


def test_dilithium_attributes():
	dss = DSS.Dilithium()

	assert hasattr(dss, "name")
	assert isinstance(dss.name, str)

	assert hasattr(dss, "variant")
	assert isinstance(dss.variant, Variant)

	assert hasattr(dss, "param_sizes")
	assert isinstance(dss.param_sizes, DssParamSizes)

	assert hasattr(dss, "keygen")
	assert isinstance(dss.keygen, Callable)

	assert hasattr(dss, "sign")
	assert isinstance(dss.sign, Callable)

	assert hasattr(dss, "verify")
	assert isinstance(dss.verify, Callable)


def test_dilithium_variants():
	dss = DSS.Dilithium()
	assert dss.variant == Variant.CLEAN

	dss = DSS.Dilithium(Variant.CLEAN)
	assert dss.variant == Variant.CLEAN

	with pytest.raises(ModuleNotFoundError):
		DSS.Dilithium(Variant.AVX2)


def test_dilithium_cryptography():
	dss = DSS.Dilithium()
	params = dss.param_sizes
	message = b"Hello World"

	public_key, secret_key = dss.keygen()

	assert isinstance(public_key, bytes)
	assert len(public_key) == params.pk_size
	assert isinstance(secret_key, bytes)
	assert len(secret_key) == params.sk_size

	signature = dss.sign(secret_key, message)

	assert isinstance(signature, bytes)
	assert len(signature) >= params.sig_size
	assert dss.verify(public_key, message, signature, raises=False)


def test_dilithium_invalid_inputs(
		invalid_keys: Callable,
		invalid_messages: Callable,
		invalid_signatures: Callable):

	dss = DSS.Dilithium()
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

	with pytest.raises(VerifyFailedError):
		dss.verify(public_key[::-1], message, signature)

	with pytest.raises(VerifyFailedError):
		dss.verify(public_key, message[::-1], signature)

	with pytest.raises(VerifyFailedError):
		dss.verify(public_key, message, signature[::-1])
