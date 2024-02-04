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
from dotmap import DotMap
from typing import Callable, Literal
from typer.testing import CliRunner
from quantcrypt.internal.cli.main import app


@pytest.fixture(scope="function")
def get_sign_args() -> Callable:
	def closure(paths: DotMap) -> list:
		return [
			"sign",
			'-s', paths.sk_file.as_posix(),
			'-i', paths.pt_file.as_posix(),
			'-S', paths.sig_file.as_posix()
		]
	return closure


@pytest.fixture(scope="function")
def get_verify_args(get_sign_args: Callable) -> Callable:
	def closure(paths: DotMap) -> list:
		args = get_sign_args(paths)
		runner = CliRunner()
		result = runner.invoke(app, args + ['-N'])
		assert result.exit_code == 0
		return [
			"verify",
			'-p', paths.pk_file.as_posix(),
			'-i', paths.pt_file.as_posix(),
			'-S', paths.sig_file.as_posix()
		]
	return closure


@pytest.fixture(scope="function")
def get_args(get_sign_args: Callable, get_verify_args: Callable) -> Callable:
	def closure(paths: DotMap, mode: Literal["SIGN", "VERIFY"]) -> list:
		func = get_sign_args if mode == "SIGN" else get_verify_args
		return func(paths)
	return closure
