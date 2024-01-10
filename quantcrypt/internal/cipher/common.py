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
from __future__ import annotations
from typing import Literal
from ..errors import *
from .. import utils


__all__ = ["ChunkSizeKB", "ChunkSizeMB", "ChunkSize"]


class ChunkSizeKB(dict):
	@utils.input_validator()
	def __init__(self, size: Literal[1, 2, 4, 8, 16, 32, 64, 128, 256, 512]):
		"""
		Converts the size argument kilobytes input value to bytes.

		:param size: The block size in kilobytes
		:return: The block size in bytes
		:raises - pydantic.ValidationError:
			If the input size value is not a valid Literal
		"""
		super().__init__(value=1024 * size)


class ChunkSizeMB(dict):
	@utils.input_validator()
	def __init__(self, size: Literal[1, 2, 4, 8, 16, 32, 64, 128, 256, 512]):
		"""
		Converts the size argument megabytes input value to bytes.

		:param size: The block size in megabytes
		:return: The block size in bytes
		:raises - pydantic.ValidationError:
			If the input size value is not a valid Literal
		"""
		super().__init__(value=1024 ** 2 * size)


class ChunkSize:
	def __init__(self):
		"""
		This class is a collection of classes and is not
		intended to be instantiated directly. You can access
		the contained KB and MB classes as attributes of this
		class.
		"""
		raise InvalidUsageError(
			"ChunkSize class is a collection of classes and "
			"is not intended to be instantiated directly."
		)
	KB = ChunkSizeKB
	MB = ChunkSizeMB
