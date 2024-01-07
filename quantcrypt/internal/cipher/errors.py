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
	"CipherDecryptError"
]


class CipherError(QuantCryptError):
	"""Base class for all Cipher errors."""


class CipherDecryptError(CipherError):
	def __init__(self):
		super().__init__("Cipher was unable to decrypt the data packet with the provided key.")
