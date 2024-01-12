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
from ..errors import QuantCryptError


__all__ = [
	"KDFError",
	"KDFOutputLimitError",
	"KDFWeakPasswordError",
	"KDFVerificationError",
	"KDFInvalidHashError",
	"KDFHashingError",
]


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
