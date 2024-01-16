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
from dataclasses import dataclass
from pydantic import Field
from typing import Literal, Type, Annotated
from ..errors import InvalidUsageError
from .. import utils


__all__ = [
	"DecryptedFileData",
	"ChunkSizeKB", "ChunkSizeMB", "ChunkSize",
	"determine_file_chunk_size"
]


@dataclass
class DecryptedFileData:
	"""
	Contains two instance attributes:
	plaintext (bytes) and header (bytes)
	"""
	plaintext: bytes = b''
	header: bytes = b''


@dataclass(frozen=True)
class ChunkSizeKB:
	value: int

	@utils.input_validator()
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

	@utils.input_validator()
	def __init__(self, size: Annotated[int, Field(ge=1, le=10)]) -> None:
		"""
		:param size: The chunk size in megabytes.
		:raises - pydantic.ValidationError:
			On invalid size argument value.
		"""
		object.__setattr__(self, 'value', 1024 ** 2 * size)


class ChunkSize:
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


def determine_file_chunk_size(file_size: int) -> ChunkSizeKB | ChunkSizeMB:
	kilo_bytes = 1024
	mega_bytes = kilo_bytes * 1024

	if file_size <= kilo_bytes * 4:
		return ChunkSizeKB(1)
	elif file_size <= kilo_bytes * 16:
		return ChunkSizeKB(4)
	elif file_size <= kilo_bytes * 64:
		return ChunkSizeKB(16)
	elif file_size <= kilo_bytes * 256:
		return ChunkSizeKB(64)
	elif file_size <= kilo_bytes * 1024:
		return ChunkSizeKB(256)

	for x in range(0, 10):
		x += 1
		if file_size <= mega_bytes * x * 100:
			return ChunkSizeMB(x)
	return ChunkSizeMB(10)
