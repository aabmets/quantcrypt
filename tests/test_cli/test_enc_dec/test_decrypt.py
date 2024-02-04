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
from typing import Callable


class TestKyber:
	@staticmethod
	def test_success(success: Callable):
		success("kyber", "DEC")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("kyber", "DEC")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("kyber", "DEC")
