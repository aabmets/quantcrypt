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
	"KeygenFailedError",
	"EncapsFailedError",
	"DecapsFailedError"
]


class QuantCryptError(Exception):
	"""Base class for all QuantCrypt errors."""
	def __init__(self, errmsg: str):
		super().__init__(errmsg)


class KeygenFailedError(QuantCryptError):
	def __init__(self):
		super().__init__("Kupydo KEM keygen failed.")


class EncapsFailedError(QuantCryptError):
	def __init__(self):
		super().__init__("Kupydo KEM encaps failed.")


class DecapsFailedError(QuantCryptError):
	def __init__(self):
		super().__init__("Kupydo KEM decaps failed.")
