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
from quantcrypt.internal.pqa.base_dss import BaseDSS
from quantcrypt.internal.pqa.base_kem import BaseKEM
from quantcrypt.internal.cli.commands import sign_verify
from quantcrypt.internal.cli.commands import enc_dec
from quantcrypt.internal.cli.commands import compile
from quantcrypt.internal.cli.commands import keygen
from quantcrypt.internal.cli.commands import remove
from quantcrypt.internal.cli.commands import info
from quantcrypt.internal.cli.main import app


@dataclass(frozen=True)
class CryptoFilePaths:
    algorithm: str
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
    def closure(pqa_class: BaseDSS | BaseKEM) -> t.Generator[CryptoFilePaths, t.Any, None]:
        algorithm = pqa_class.armor_name().lower()
        cfp_dict = dict(
            algorithm=algorithm,
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
        for item in alt_tmp_path.iterdir():
            item.unlink()
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
            info=info.info_app,
            keygen=keygen.keygen_app,
            encrypt=enc_dec.enc_app,
            decrypt=enc_dec.dec_app,
            sign=sign_verify.sign_app,
            verify=sign_verify.verify_app,
            compile=compile.compile_app,
            remove=remove.remove_app
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
