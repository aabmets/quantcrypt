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

from quantcrypt.internal import constants as const
from quantcrypt.errors import (
	QuantCryptError,
	InvalidUsageError,
	InvalidArgsError,
	UnsupportedPlatformError,

	PQAError,
	PQAImportError,
	PQAUnsupportedAlgoError,
	PQAKeyArmorError,
	KEMKeygenFailedError,
	KEMEncapsFailedError,
	KEMDecapsFailedError,
	DSSKeygenFailedError,
	DSSSignFailedError,
	DSSVerifyFailedError,

	KDFError,
	KDFOutputLimitError,
	KDFWeakPasswordError,
	KDFVerificationError,
	KDFInvalidHashError,
	KDFHashingError,

	CipherError,
	CipherStateError,
	CipherVerifyError,
	CipherChunkSizeError,
	CipherPaddingError
)


def test_error_instantiation():
	assert QuantCryptError()
	assert InvalidUsageError()
	assert InvalidArgsError()
	assert UnsupportedPlatformError()

	assert PQAError()
	assert PQAImportError(const.SupportedAlgos[0], const.PQAVariant.REF)
	assert PQAUnsupportedAlgoError("asdfg")
	assert PQAKeyArmorError("armor")
	assert PQAKeyArmorError("dearmor")
	assert KEMKeygenFailedError()
	assert KEMEncapsFailedError()
	assert KEMDecapsFailedError()
	assert DSSKeygenFailedError()
	assert DSSSignFailedError()
	assert DSSVerifyFailedError()

	assert KDFError()
	assert KDFOutputLimitError(0)
	assert KDFWeakPasswordError()
	assert KDFVerificationError()
	assert KDFInvalidHashError()
	assert KDFHashingError()

	assert CipherError()
	assert CipherStateError()
	assert CipherVerifyError()
	assert CipherChunkSizeError()
	assert CipherPaddingError()
