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
import tomllib
from dotmap import DotMap
from typer.testing import CliRunner
from quantcrypt.internal import utils
from quantcrypt.internal.cli.main import app


@pytest.fixture(name="project", scope="module")
def fixture_project() -> DotMap:
	path = utils.search_upwards("pyproject.toml")
	contents = tomllib.loads(path.read_text())
	return DotMap(contents["project"])


def test_main_version(project: DotMap):
	runner = CliRunner()
	result = runner.invoke(app, ["--version"])

	assert result.exit_code == 0
	assert result.stdout.strip() == project.version


def test_main_info(project: DotMap):
	runner = CliRunner()
	result = runner.invoke(app, ["info"])

	assert result.exit_code == 0
	assert project.name in result.stdout
	assert project.version in result.stdout
	assert project.description in result.stdout
	assert project.license in result.stdout
	assert project.urls.Repository in result.stdout

	author = project.authors[0]
	assert author.name in result.stdout
	assert author.email in result.stdout
