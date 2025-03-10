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

import platform
from typing import Literal


__all__ = [
	"QuantCryptError",
	"InvalidUsageError",
	"InvalidArgsError",
	"UnsupportedPlatformError",
	"PQAError",
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
]


class QuantCryptError(Exception):
	"""Base class for all QuantCrypt errors."""


class InvalidUsageError(QuantCryptError):
	def __init__(self, message: str = None):
		super().__init__(message or "Invalid usage of object.")


class InvalidArgsError(QuantCryptError):
	def __init__(self, message: str = None):
		super().__init__(message or "Method received invalid arguments.")


class UnsupportedPlatformError(QuantCryptError):
	def __init__(self):
		super().__init__(f"Operating system '{platform.system()}' not supported!")


class PQAError(QuantCryptError):
	"""Base class for all PQC errors."""


class PQAKeyArmorError(PQAError):
	def __init__(self, verb: Literal["armor", "dearmor"]):
		super().__init__(f"QuantCrypt will not {verb} a corrupted key.")


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
	"""Base class for all KDF errors."""


class KDFOutputLimitError(KDFError):
	def __init__(self, limit: int):
		super().__init__(f"Not allowed to derive more than {limit} bytes of keys from one master key.")


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
