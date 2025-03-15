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

from quantcrypt.internal.errors import (
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


__all__ = [
    "QuantCryptError",
    "InvalidUsageError",
    "InvalidArgsError",
    "UnsupportedPlatformError",

    "PQAError",
    "PQAImportError",
    "PQAUnsupportedAlgoError",
    "PQAKeyArmorError",
    "KEMKeygenFailedError",
    "KEMEncapsFailedError",
    "KEMDecapsFailedError",
    "DSSKeygenFailedError",
    "DSSSignFailedError",
    "DSSVerifyFailedError",

    "KDFError",
    "KDFOutputLimitError",
    "KDFWeakPasswordError",
    "KDFVerificationError",
    "KDFInvalidHashError",
    "KDFHashingError",

    "CipherError",
    "CipherStateError",
    "CipherVerifyError",
    "CipherChunkSizeError",
    "CipherPaddingError"
]
