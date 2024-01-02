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
__all__ = [
	"QuantCryptError",
	"InvalidArgsError",
	"PQAError",
	"KEMKeygenFailedError",
	"KEMEncapsFailedError",
	"KEMDecapsFailedError",
	"DSSKeygenFailedError",
	"DSSSignFailedError",
	"DSSVerifyFailedError",
	"KDFWeakPasswordError",
	"KDFVerificationError",
	"KDFInvalidHashError",
	"KDFHashingError",
	"CipherError",
	"CipherDecryptionError"
]


class QuantCryptError(Exception):
	"""Base class for all QuantCrypt errors."""


class InvalidArgsError(QuantCryptError):
	def __init__(self):
		super().__init__("QuantCrypt method received an invalid argument.")


class PQAError(QuantCryptError):
	"""Base class for all QuantCrypt PQA errors."""


class KEMKeygenFailedError(PQAError):
	def __init__(self):
		super().__init__("QuantCrypt KEM keygen failed.")


class KEMEncapsFailedError(PQAError):
	def __init__(self):
		super().__init__("QuantCrypt KEM encaps failed.")


class KEMDecapsFailedError(PQAError):
	def __init__(self):
		super().__init__("QuantCrypt KEM decaps failed.")


class DSSKeygenFailedError(PQAError):
	def __init__(self):
		super().__init__("QuantCrypt DSS keygen failed.")


class DSSSignFailedError(PQAError):
	def __init__(self):
		super().__init__("QuantCrypt DSS sign failed.")


class DSSVerifyFailedError(PQAError):
	def __init__(self):
		super().__init__("QuantCrypt DSS verify failed.")


class KDFError(QuantCryptError):
	"""Base class for all QuantCrypt KDF errors."""


class KDFWeakPasswordError(KDFError):
	def __init__(self):
		super().__init__("Weak passwords are not allowed.")


class KDFVerificationError(KDFError):
	def __init__(self):
		super().__init__("KDF failed to verify the password against the provided public hash.")


class KDFInvalidHashError(KDFError):
	def __init__(self):
		super().__init__("KDF was provided with an invalid hash for verification.")


class KDFHashingError(KDFError):
	def __init__(self):
		super().__init__("KDF was unable to hash the password due to an internal error.")


class CipherError(QuantCryptError):
	"""Base class for all QuantCrypt Cipher errors."""


class CipherDecryptionError(CipherError):
	def __init__(self):
		super().__init__("Cipher was unable to decrypt the data packet with the provided key.")
