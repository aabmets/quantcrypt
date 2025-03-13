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

import os
import pytest
from typing import Callable
from dotmap import DotMap
from pathlib import Path
from typer.testing import CliRunner
from quantcrypt.internal import constants as const
from quantcrypt.internal.cli.commands.keygen import app


@pytest.fixture(name="success", scope="function")
def fixture_success(tmp_path: Path, cli_message: DotMap) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, [algo_name], input="n\n")
		assert result.exit_code == 0
		assert cli_message.cancelled in result.stdout

		result = runner.invoke(app, [algo_name], input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		pk_file = tmp_path / f"{algo_name}-pubkey.qc"
		sk_file = tmp_path / f"{algo_name}-seckey.qc"

		assert pk_file.is_file()
		assert sk_file.is_file()

	return closure


@pytest.fixture(name="dry_run", scope="function")
def fixture_dry_run(tmp_path: Path) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, ["-D", algo_name], input="y\n")
		assert result.exit_code == 0
		assert "DRY RUN MODE" in result.stdout

	return closure


@pytest.fixture(name="overwrite", scope="function")
def fixture_overwrite(tmp_path: Path, cli_message: DotMap) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, [algo_name], input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		result = runner.invoke(app, [algo_name], input="y\nn\n")
		assert result.exit_code == 0
		assert cli_message.cancelled in result.stdout

		result = runner.invoke(app, [algo_name], input="y\ny\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		result = runner.invoke(app, ["-N", algo_name])
		assert result.exit_code == 1
		assert cli_message.ow_error in result.stdout

		result = runner.invoke(app, ["-N", "-W", algo_name])
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

	return closure


@pytest.fixture(name="identifier", scope="function")
def fixture_identifier(tmp_path: Path, cli_message: DotMap) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, ["-i", "pytest", algo_name], input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		pk_file = tmp_path / f"pytest-{algo_name}-pubkey.qc"
		sk_file = tmp_path / f"pytest-{algo_name}-seckey.qc"

		assert pk_file.is_file()
		assert sk_file.is_file()

		result = runner.invoke(app, ["-i", "!", algo_name])
		assert result.exit_code == 1
		assert "Only characters [a-z, A-Z, 0-9]" in result.stdout

		result = runner.invoke(app, ["-i", "x" * 16, algo_name])
		assert result.exit_code == 1
		assert "longer than 15 characters!" in result.stdout

	return closure


@pytest.fixture(name="directory", scope="function")
def fixture_directory(tmp_path: Path, cli_message: DotMap) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, ["-d", "pytest", algo_name], input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		pk_file = tmp_path / f"pytest/{algo_name}-pubkey.qc"
		sk_file = tmp_path / f"pytest/{algo_name}-seckey.qc"

		assert pk_file.is_file()
		assert sk_file.is_file()

	return closure



class Test_Keygen:
	algos = const.SupportedAlgos.armor_names()

	@classmethod
	def test_success(cls, success: Callable):
		for algo in cls.algos:
			success(algo)

	@classmethod
	def test_dry_run(cls, dry_run: Callable):
		for algo in cls.algos:
			dry_run(algo)

	@classmethod
	def test_overwrite(cls, overwrite: Callable):
		for algo in cls.algos:
			overwrite(algo)

	@classmethod
	def test_identifier(cls, identifier: Callable):
		for algo in cls.algos:
			identifier(algo)

	@classmethod
	def test_directory(cls, directory: Callable):
		for algo in cls.algos:
			directory(algo)
