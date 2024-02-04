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
from typer.testing import CliRunner
from quantcrypt.internal.cli.commands.optimize import app


def test_optimize_dry_run():
	runner = CliRunner()
	result = runner.invoke(app, ["-D"], input="y\n")
	assert result.exit_code == 0
	assert "DRY RUN MODE" in result.stdout


def test_optimize_decline():
	runner = CliRunner()
	result = runner.invoke(app, ["-D"], input="n\n")
	assert result.exit_code == 0
	assert "Operation cancelled." in result.stdout
