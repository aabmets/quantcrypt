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
from typing import Literal, Type, Annotated, Optional
from pydantic import Field, validate_call
from dataclasses import dataclass
from ..errors import InvalidUsageError


__all__ = ["ChunkSizeKB", "ChunkSizeMB", "ChunkSize"]


@dataclass(frozen=True)
class ChunkSizeKB:
	value: int

	@validate_call
	def __init__(self, size: Literal[1, 2, 4, 8, 16, 32, 64, 128, 256]) -> None:
		"""
		:param size: The chunk size in kilobytes.
		:raises - pydantic.ValidationError:
			On invalid size argument value.
		"""
		object.__setattr__(self, 'value', 1024 * size)


@dataclass(frozen=True)
class ChunkSizeMB:
	value: int

	@validate_call
	def __init__(self, size: Literal[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) -> None:
		"""
		:param size: The chunk size in megabytes.
		:raises - pydantic.ValidationError:
			On invalid size argument value.
		"""
		object.__setattr__(self, 'value', 1024 ** 2 * size)


class ChunkSize:
	Atd = Annotated[
		Optional[ChunkSizeKB | ChunkSizeMB],
		Field(default=None)
	]

	def __init__(self):
		"""
		This class is a collection of classes and is not
		intended to be instantiated directly. You can access
		the contained **KB** and **MB** classes as attributes
		of this class.
		"""
		raise InvalidUsageError(
			"ChunkSize class is a collection of classes and "
			"is not intended to be instantiated directly."
		)
	KB: Type[ChunkSizeKB] = ChunkSizeKB
	MB: Type[ChunkSizeMB] = ChunkSizeMB

	@staticmethod
	def determine_from_data_size(data_size: int) -> ChunkSizeKB | ChunkSizeMB:
		kilo_bytes = 1024
		mega_bytes = kilo_bytes * 1024

		if data_size <= kilo_bytes * 4:
			return ChunkSizeKB(1)
		elif data_size <= kilo_bytes * 16:
			return ChunkSizeKB(4)
		elif data_size <= kilo_bytes * 64:
			return ChunkSizeKB(16)
		elif data_size <= kilo_bytes * 256:
			return ChunkSizeKB(64)
		elif data_size <= kilo_bytes * 1024:
			return ChunkSizeKB(256)

		for x in range(0, 10):
			x += 1
			if data_size <= mega_bytes * x * 100:
				return ChunkSizeMB(x)
		return ChunkSizeMB(10)
