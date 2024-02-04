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
from typing import Callable, Literal, cast
from typer.testing import CliRunner
from quantcrypt.internal.cli.commands.keygen import app
from quantcrypt.internal.cli.commands import helpers as hlp


@pytest.fixture(scope="function")
def success(tmp_path: Path, cli_message: DotMap) -> Callable:
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


@pytest.fixture(scope="function")
def dry_run(tmp_path: Path) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, [algo_name, "-D"], input="y\n")
		assert result.exit_code == 0
		assert "DRY RUN MODE" in result.stdout

	return closure


@pytest.fixture(scope="function")
def overwrite(tmp_path: Path, cli_message: DotMap) -> Callable:
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

		result = runner.invoke(app, [algo_name, "-N"])
		assert result.exit_code == 1
		assert cli_message.ow_error in result.stdout

		result = runner.invoke(app, [algo_name, "-N", "-W"])
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

	return closure


@pytest.fixture(scope="function")
def identifier(tmp_path: Path, cli_message: DotMap) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, [algo_name, "-i", "pytest"], input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		pk_file = tmp_path / f"pytest-{algo_name}-pubkey.qc"
		sk_file = tmp_path / f"pytest-{algo_name}-seckey.qc"

		assert pk_file.is_file()
		assert sk_file.is_file()

		result = runner.invoke(app, [algo_name, "-i", "!"])
		assert result.exit_code == 1
		assert "Only characters [a-z, A-Z, 0-9]" in result.stdout

		result = runner.invoke(app, [algo_name, "-i", "x" * 16])
		assert result.exit_code == 1
		assert "longer than 15 characters!" in result.stdout

	return closure


@pytest.fixture(scope="function")
def directory(tmp_path: Path, cli_message: DotMap) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, [algo_name, "-d", "pytest"], input="y\n")
		assert result.exit_code == 0
		assert cli_message.success in result.stdout

		pk_file = tmp_path / f"pytest/{algo_name}-pubkey.qc"
		sk_file = tmp_path / f"pytest/{algo_name}-seckey.qc"

		assert pk_file.is_file()
		assert sk_file.is_file()

	return closure


@pytest.fixture(scope="function")
def armoring(tmp_path: Path) -> Callable:
	def closure(algo_name: str) -> None:
		os.chdir(tmp_path)
		runner = CliRunner()

		result = runner.invoke(app, [algo_name, "-N"])
		assert result.exit_code == 0

		pk_file = tmp_path / f"{algo_name}-pubkey.qc"
		sk_file = tmp_path / f"{algo_name}-seckey.qc"
		determinator = (
			hlp.determine_kem_class
			if algo_name in ["kyber"] else
			hlp.determine_dss_class
		)
		for file, exp in [(pk_file, "PUBLIC"), (sk_file, "SECRET")]:
			data = file.read_text(encoding="UTF-8")
			copy = data.replace(algo_name.upper(), "ASDFG")
			lit_exp = cast(exp, Literal)

			with pytest.raises(SystemExit, match="1"):
				determinator("", lit_exp)

			with pytest.raises(SystemExit, match="1"):
				determinator(copy, lit_exp)

			copy = data.replace(exp, "ASDFG")

			with pytest.raises(SystemExit, match="1"):
				determinator(copy, lit_exp)

			copy = data \
				.replace(algo_name.upper(), "ASDFG", 1) \
				.replace(algo_name.upper(), "QWERTY") \
				.replace("ASDFG", algo_name.upper())

			with pytest.raises(SystemExit, match="1"):
				determinator(copy, lit_exp)

			match exp:
				case "PUBLIC":
					with pytest.raises(SystemExit, match="1"):
						determinator(data, "SECRET")
				case "SECRET":
					with pytest.raises(SystemExit, match="1"):
						determinator(data, "PUBLIC")

	return closure
