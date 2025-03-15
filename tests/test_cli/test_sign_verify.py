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
from quantcrypt.internal import constants as const
from .conftest import CryptoFilePaths, CLIMessages


class TestSignVerify:
    algos = const.SupportedAlgos.armor_names(const.PQAType.DSS)

    @staticmethod
    def options(cfp: CryptoFilePaths) -> tuple[list[str], list[str]]:
        sign_opt = [
            '-s', cfp.secret_key_fp,
            '-i', cfp.plaintext_fp,
            '-S', cfp.signature_fp
        ]
        verify_opt = [
            '-p', cfp.public_key_fp,
            '-i', cfp.plaintext_fp,
            '-S', cfp.signature_fp
        ]
        return sign_opt, verify_opt

    @classmethod
    def test_sign_verify(cls, cfp_setup, cli_runner) -> None:
        print()
        for algorithm in cls.algos:
            print(f"Testing {algorithm} signature verification in CLI")
            with cfp_setup(algorithm) as cfp:
                cli_runner("keygen", ['-N', algorithm])
                cls.flow(cfp, cli_runner)

    @classmethod
    def flow(cls, cfp: CryptoFilePaths, cli_runner: Callable) -> None:
        sign_opt, verify_opt = cls.options(cfp)

        cli_runner("sign", sign_opt, "n\n", CLIMessages.CANCELLED)
        cli_runner("sign", sign_opt + ['-D'], "y\n", CLIMessages.DRYRUN)
        cli_runner("sign", sign_opt, "y\n", CLIMessages.SUCCESS)
        cli_runner("sign", sign_opt, "y\nn\n", CLIMessages.CANCELLED)
        cli_runner("sign", sign_opt, "y\ny\n", CLIMessages.SUCCESS)
        cli_runner("sign", sign_opt + ['-N'], "", CLIMessages.ERROR)
        cli_runner("sign", sign_opt + ['-N', '-W'], "", CLIMessages.SUCCESS)

        cli_runner("verify", verify_opt, "n\n", CLIMessages.CANCELLED)
        cli_runner("verify", verify_opt + ['-D'], "y\n", CLIMessages.DRYRUN)
        cli_runner("verify", verify_opt, "y\n", CLIMessages.SUCCESS)
