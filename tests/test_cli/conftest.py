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
import typing as t
from pathlib import Path
from dataclasses import dataclass
from contextlib import contextmanager
from collections.abc import Callable
from typer.testing import CliRunner, Result
from quantcrypt.internal.cli.main import app
from quantcrypt.internal.cli import commands as cmd


@dataclass(frozen=True)
class CryptoFilePaths:
    public_key_fp: str
    secret_key_fp: str
    ciphertext_fp: str
    plaintext_fp: str
    signature_fp: str
    ptf_data: bytes


class CLIMessages:
    ERROR = "QuantCrypt Error"
    SUCCESS = "Operation successful"
    CANCELLED = "Operation cancelled"
    DRYRUN = "DRY RUN MODE"


CLIMessages = CLIMessages()
ValidCommands = t.Literal["main", "info", "encrypt", "decrypt", "sign", "verify"]


@pytest.fixture(name="cfp_setup", scope="function")
def fixture_cfp_setup(alt_tmp_path) -> Callable[..., t.ContextManager[CryptoFilePaths]]:
    @contextmanager
    def closure(algorithm: str) -> t.Generator[CryptoFilePaths, t.Any, None]:
        cfp_dict = dict(
            public_key_fp=alt_tmp_path / f"{algorithm}-pubkey.qc",
            secret_key_fp=alt_tmp_path / f"{algorithm}-seckey.qc",
            ciphertext_fp=alt_tmp_path / "ciphertext.kptn",
            plaintext_fp=alt_tmp_path / "plaintext.bin",
            signature_fp=alt_tmp_path / "signature.sig",
            ptf_data=os.urandom(1024)
        )
        cfp = CryptoFilePaths(**{
            k: v.as_posix() if isinstance(v, Path) else v
            for k, v in cfp_dict.items()
        })
        with open(cfp.plaintext_fp, "wb") as file:
            file.write(cfp.ptf_data)
        cwd = os.getcwd()
        os.chdir(alt_tmp_path)
        yield cfp
        os.chdir(cwd)
    return closure


@pytest.fixture(name="cli_runner", scope="function")
def fixture_cli_runner() -> Callable[..., Result]:
    def closure(
            command: ValidCommands = "main",
            options: list[str] = None,
            user_input: str = None,
            expected_stdout: str = None,
            debug: bool = False
    ) -> Result:
        runner = CliRunner()
        _app = dict(
            main=app,
            info=cmd.info_app,
            keygen=cmd.keygen_app,
            encrypt=cmd.enc_app,
            decrypt=cmd.dec_app,
            sign=cmd.sign_app,
            verify=cmd.verify_app,
            compile=cmd.compile_app,
        )[command]
        result = runner.invoke(_app, options, input=user_input)
        if debug:
            print(result.output)
        expected_exit_code = 1
        if expected_stdout != CLIMessages.ERROR:
            expected_exit_code = 0
        assert result.exit_code == expected_exit_code
        assert (expected_stdout or '') in result.stdout
        return result
    return closure
