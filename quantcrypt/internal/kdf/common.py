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
from dotmap import DotMap
from pydantic import Field
from typing import Type, Annotated, Literal
from ..errors import InvalidUsageError
from .. import utils


__all__ = ["MemCostMB", "MemCostGB", "MemCost", "KDFParams"]


class MemCostMB(dict):
	@utils.input_validator()
	def __init__(self, size: Literal[32, 64, 128, 256, 512]) -> None:
		"""
		Converts the size input argument value of megabytes to kilobytes.

		:param size: The memory cost size in megabytes
		:return: The memory cost in kilobytes
		:raises - pydantic.ValidationError:
			If the input size value is not a valid Literal
		"""
		super().__init__(value=1024 * size)


class MemCostGB(dict):
	@utils.input_validator()
	def __init__(self, size: Literal[1, 2, 3, 4, 5, 6, 7, 8]) -> None:
		"""
		Converts the size input argument value of gigabytes to kilobytes.

		:param size: The memory cost size in gigabytes
		:return: The memory cost in kilobytes
		:raises - pydantic.ValidationError:
			If the input size value is not a valid Literal
		"""
		super().__init__(value=1024 ** 2 * size)


class MemCost:
	def __init__(self):
		"""
		This class is a collection of classes and is not
		intended to be instantiated directly. You can access
		the contained **MB** and **GB** classes as attributes
		of this class.
		"""
		raise InvalidUsageError(
			"MemCost class is a collection of classes and "
			"is not intended to be instantiated directly."
		)
	MB: Type[MemCostMB] = MemCostMB
	GB: Type[MemCostGB] = MemCostGB


class KDFParams(DotMap):
	@utils.input_validator()
	def __init__(
			self,
			memory_cost: MemCostMB | MemCostGB,
			parallelism: Annotated[int, Field(gt=0)],
			time_cost: Annotated[int, Field(gt=0)],
			hash_len: Annotated[int, Field(ge=16, le=64)] = 32,
			salt_len: Annotated[int, Field(ge=16, le=64)] = 32
	) -> None:
		"""
		Custom parameters for altering the security
		level of key derivation functions.

		:param memory_cost: The amount of memory the KDF must use.
		:param parallelism: Up to how many threads the KDF can use.
		:param time_cost: The amount of iterations the KDF must run.
		:param hash_len: The length of the generated hash, in bytes.
		:param salt_len: The length of the generated salt, in bytes.
		"""
		memory_cost = memory_cost.get("value")
		super().__init__({
			k: v for k, v in locals().items()
			if k not in ["self", "__class__"]
		})
