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

from quantcrypt.internal import constants as const
from quantcrypt.internal.cli.commands import compile
from .conftest import CLIMessages


class MockedProcess:
    def __init__(self, returncode: int):
        self._returncode = returncode

    @property
    def stdout(self) -> list[str]:
        return [
            "Some garbage output from CFFI...",
            f"{const.SubprocTag}Compiling clean variant of MLKEM512...",
            "More garbage output from CFFI..."
        ]

    @property
    def returncode(self) -> int:
        return int(self._returncode)

    def wait(self) -> None:
        return


class MockedCompiler:
    _returncode = 1

    @classmethod
    def run(cls, *_, **kwargs) -> MockedProcess:
        assert "in_subprocess" in kwargs and kwargs["in_subprocess"] is True
        cls._returncode = not cls._returncode
        return MockedProcess(cls._returncode)


def test_compile(cli_runner, alt_tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(compile, "Compiler", MockedCompiler)

    cli_runner("compile", [], "n\n", CLIMessages.CANCELLED)
    cli_runner("compile", ['-o', 'mlkem512'], "y\n", CLIMessages.SUCCESS)
    cli_runner("compile", ['-D', 'mlkem512'], "y\n", CLIMessages.DRYRUN)
    cli_runner("compile", ['-N', 'mlkem512'], "", CLIMessages.ERROR)
    cli_runner("compile", ['-N', 'mlkem512'], "", CLIMessages.SUCCESS)
