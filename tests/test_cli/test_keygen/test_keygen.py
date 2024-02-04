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
		success("kyber")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("kyber")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("kyber")

	@staticmethod
	def test_identifier(identifier: Callable):
		identifier("kyber")

	@staticmethod
	def test_armoring(armoring: Callable):
		armoring("kyber")


class TestDilithium:
	@staticmethod
	def test_success(success: Callable):
		success("dilithium")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("dilithium")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("dilithium")

	@staticmethod
	def test_identifier(identifier: Callable):
		identifier("dilithium")

	@staticmethod
	def test_armoring(armoring: Callable):
		armoring("dilithium")


class TestFalcon:
	@staticmethod
	def test_success(success: Callable):
		success("falcon")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("falcon")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("falcon")

	@staticmethod
	def test_identifier(identifier: Callable):
		identifier("falcon")

	@staticmethod
	def test_armoring(armoring: Callable):
		armoring("falcon")


class TestFastSphincs:
	@staticmethod
	def test_success(success: Callable):
		success("fastsphincs")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("fastsphincs")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("fastsphincs")

	@staticmethod
	def test_identifier(identifier: Callable):
		identifier("fastsphincs")

	@staticmethod
	def test_armoring(armoring: Callable):
		armoring("fastsphincs")


class TestSmallSphincs:
	@staticmethod
	def test_success(success: Callable):
		success("smallsphincs")

	@staticmethod
	def test_dry_run(dry_run: Callable):
		dry_run("smallsphincs")

	@staticmethod
	def test_overwrite(overwrite: Callable):
		overwrite("smallsphincs")

	@staticmethod
	def test_identifier(identifier: Callable):
		identifier("smallsphincs")

	@staticmethod
	def test_armoring(armoring: Callable):
		armoring("smallsphincs")
