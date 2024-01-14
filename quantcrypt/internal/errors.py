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
	"InvalidUsageError",
	"InvalidArgsError"
]


class QuantCryptError(Exception):
	"""Base class for all QuantCrypt errors."""


class InvalidUsageError(QuantCryptError):
	def __init__(self, message: str = None):
		super().__init__(message or "Invalid usage of object.")


class InvalidArgsError(QuantCryptError):
	def __init__(self, message: str = None):
		super().__init__(message or "Method received invalid arguments.")
