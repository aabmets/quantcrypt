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

from typing import Literal


__all__ = [
	"QuantCryptError",
	"InvalidUsageError",
	"InvalidArgsError",
	"PQAError",
	"PQAKeyArmorError",
	"KEMKeygenFailedError",
	"KEMEncapsFailedError",
	"KEMDecapsFailedError",
	"DSSKeygenFailedError",
	"DSSSignFailedError",
	"DSSVerifyFailedError"
]


class QuantCryptError(Exception):
	"""Base class for all QuantCrypt errors."""


class InvalidUsageError(QuantCryptError):
	def __init__(self, message: str = None):
		super().__init__(message or "Invalid usage of object.")


class InvalidArgsError(QuantCryptError):
	def __init__(self, message: str = None):
		super().__init__(message or "Method received invalid arguments.")


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
