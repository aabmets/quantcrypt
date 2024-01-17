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
from .. import utils
from ..errors import InvalidUsageError
from typing import Literal, Type


__all__ = ["MemCostMB", "MemCostGB", "MemCost"]


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
