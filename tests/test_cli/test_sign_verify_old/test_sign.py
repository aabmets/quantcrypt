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
		success("dilithium", "SIGN")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("dilithium", "SIGN")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("dilithium", "SIGN")


class TestFalcon:
	@staticmethod
	def test_success(success: Callable):
		success("falcon", "SIGN")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("falcon", "SIGN")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("falcon", "SIGN")


class TestFastSphincs:
	@staticmethod
	def test_success(success: Callable):
		success("fastsphincs", "SIGN")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("fastsphincs", "SIGN")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("fastsphincs", "SIGN")


class TestSmallSphincs:
	@staticmethod
	def test_success(success: Callable):
		success("smallsphincs", "SIGN")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("smallsphincs", "SIGN")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("smallsphincs", "SIGN")
