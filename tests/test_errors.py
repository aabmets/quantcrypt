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
from quantcrypt.errors import (
	QuantCryptError,
	InvalidUsageError,
	InvalidArgsError,

	CipherError,
	CipherStateError,
	CipherVerifyError,
	CipherChunkSizeError,
	CipherPaddingError,

	KDFError,
	KDFOutputLimitError,
	KDFWeakPasswordError,
	KDFVerificationError,
	KDFInvalidHashError,
	KDFHashingError,

	PQAError,
	PQAKeyArmorError,
	KEMKeygenFailedError,
	KEMEncapsFailedError,
	KEMDecapsFailedError,
	DSSKeygenFailedError,
	DSSSignFailedError,
	DSSVerifyFailedError
)


def test_error_instantiation():
	assert QuantCryptError()
	assert InvalidUsageError()
	assert InvalidArgsError()

	assert CipherError()
	assert CipherStateError()
	assert CipherVerifyError()
	assert CipherChunkSizeError()
	assert CipherPaddingError()

	assert KDFError()
	assert KDFOutputLimitError(0)
	assert KDFWeakPasswordError()
	assert KDFVerificationError()
	assert KDFInvalidHashError()
	assert KDFHashingError()

	assert PQAError()
	assert PQAKeyArmorError("armor")
	assert PQAKeyArmorError("dearmor")
	assert KEMKeygenFailedError()
	assert KEMEncapsFailedError()
	assert KEMDecapsFailedError()
	assert DSSKeygenFailedError()
	assert DSSSignFailedError()
	assert DSSVerifyFailedError()
