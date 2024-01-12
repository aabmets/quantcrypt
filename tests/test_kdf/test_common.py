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
import pytest
from typing import Literal, cast
from pydantic import ValidationError
from quantcrypt.internal.kdf.common import MemCost


def test_mem_cost_mb_values():
	for value in range(513):
		c_val = cast(Literal, value)
		if value in [32, 64, 128, 256, 512]:
			assert MemCost.MB(c_val).get("value") == 1024 * value
		else:
			with pytest.raises(ValidationError):
				MemCost.MB(c_val)


def test_mem_cost_gb_values():
	for value in range(33):
		c_val = cast(Literal, value)
		if value in [1, 2, 4, 8, 16, 32]:
			assert MemCost.GB(c_val).get("value") == 1024 ** 2 * value
		else:
			with pytest.raises(ValidationError):
				MemCost.GB(c_val)
