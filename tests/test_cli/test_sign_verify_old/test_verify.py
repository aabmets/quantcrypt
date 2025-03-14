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


class TestDilithium:
	@staticmethod
	def test_success(success: Callable):
		success("dilithium", "VERIFY")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("dilithium", "VERIFY")


class TestFalcon:
	@staticmethod
	def test_success(success: Callable):
		success("falcon", "VERIFY")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("falcon", "VERIFY")


class TestFastSphincs:
	@staticmethod
	def test_success(success: Callable):
		success("fastsphincs", "VERIFY")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("fastsphincs", "VERIFY")


class TestSmallSphincs:
	@staticmethod
	def test_success(success: Callable):
		success("smallsphincs", "VERIFY")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("smallsphincs", "VERIFY")
