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
	"CipherError",
	"CipherStateError",
	"CipherVerifyError",
	"CipherChunkSizeError",
	"CipherPaddingError"
]


class CipherError(QuantCryptError):
	"""Base class for all Cipher errors."""


class CipherStateError(CipherError):
	def __init__(self):
		super().__init__("Cannot call this method in the current cipher state.")


class CipherVerifyError(CipherError):
	def __init__(self):
		super().__init__("Cannot verify the decrypted data with the provided digest.")


class CipherChunkSizeError(CipherError):
	def __init__(self):
		super().__init__("Data is larger than the allowed chunk size.")


class CipherPaddingError(CipherError):
	def __init__(self):
		super().__init__("The padding of the decrypted plaintext is incorrect.")
