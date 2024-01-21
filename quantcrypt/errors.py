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
from .internal.errors import (
	QuantCryptError,
	InvalidUsageError,
	InvalidArgsError
)
from .internal.cipher.errors import (
	CipherError,
	CipherStateError,
	CipherVerifyError,
	CipherChunkSizeError,
	CipherPaddingError
)
from .internal.kdf.errors import (
	KDFError,
	KDFOutputLimitError,
	KDFWeakPasswordError,
	KDFVerificationError,
	KDFInvalidHashError,
	KDFHashingError
)
from .internal.pqa.errors import (
	PQAError,
	PQAKeyArmorError,
	KEMKeygenFailedError,
	KEMEncapsFailedError,
	KEMDecapsFailedError,
	DSSKeygenFailedError,
	DSSSignFailedError,
	DSSVerifyFailedError
)


__all__ = [
	"QuantCryptError",
	"InvalidUsageError",
	"InvalidArgsError",
	"CipherError",
	"CipherStateError",
	"CipherVerifyError",
	"CipherChunkSizeError",
	"CipherPaddingError",
	"KDFError",
	"KDFOutputLimitError",
	"KDFWeakPasswordError",
	"KDFVerificationError",
	"KDFInvalidHashError",
	"KDFHashingError",
	"PQAError",
	"PQAKeyArmorError",
	"KEMKeygenFailedError",
	"KEMEncapsFailedError",
	"KEMDecapsFailedError",
	"DSSKeygenFailedError",
	"DSSSignFailedError",
	"DSSVerifyFailedError"
]
