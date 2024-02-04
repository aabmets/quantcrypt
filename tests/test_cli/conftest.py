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
from pathlib import Path
from dotmap import DotMap
from typing import Callable
from typer.testing import CliRunner
from quantcrypt.internal.cli.main import app


@pytest.fixture(scope="package")
def cli_message() -> DotMap:
	return DotMap(
		success="Operation successful!",
		cancelled="Operation cancelled.",
		ow_error="Must explicitly enable file overwriting"
	)


@pytest.fixture(scope="function")
def get_paths(tmp_path: Path) -> Callable:
	def closure(algo_name: str) -> DotMap:
		os.chdir(tmp_path)
		runner = CliRunner()
		result = runner.invoke(app, ["keygen", algo_name], input="y\n")
		assert result.exit_code == 0

		paths = DotMap(
			pk_file=tmp_path / f"{algo_name}-pubkey.qc",
			sk_file=tmp_path / f"{algo_name}-seckey.qc",
			pt_file=tmp_path / "data_file.bin",
			ct_file=tmp_path / "data_file.kptn",
			sig_file=tmp_path / "data_file.sig"
		)
		with paths.pt_file.open("wb") as file:
			file.write(os.urandom(1024))
		return paths

	return closure


@pytest.fixture(scope="function")
def success(get_paths: Callable, get_args: Callable, cli_message: DotMap) -> Callable:
	def closure(algo_name: str, mode: str) -> None:
		paths = get_paths(algo_name)
		args = get_args(paths, mode)
		runner = CliRunner()

		result = runner.invoke(app, args, input="n\n")
		assert result.exit_code == 0
		assert cli_message.cancelled in result.stdout

		result = runner.invoke(app, args, input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

	return closure


@pytest.fixture(scope="function")
def dry_run(get_paths: Callable, get_args: Callable) -> Callable:
	def closure(algo_name: str, mode: str) -> None:
		paths = get_paths(algo_name)
		args = get_args(paths, mode)
		runner = CliRunner()

		result = runner.invoke(app, args + ['-D'], input="y\n")
		assert result.exit_code == 0
		assert "DRY RUN MODE" in result.stdout

	return closure


@pytest.fixture(scope="function")
def overwrite(get_paths: Callable, get_args: Callable, cli_message: DotMap) -> Callable:
	def closure(algo_name: str, mode: str) -> None:
		paths = get_paths(algo_name)
		args = get_args(paths, mode)
		runner = CliRunner()

		result = runner.invoke(app, args, input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		result = runner.invoke(app, args, input="y\nn\n")
		assert result.exit_code == 0
		assert cli_message.cancelled in result.stdout

		result = runner.invoke(app, args, input="y\ny\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		result = runner.invoke(app, args + ['-N'])
		assert result.exit_code == 1
		assert cli_message.ow_error in result.stdout

		result = runner.invoke(app, args + ['-N', '-W'])
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

	return closure
