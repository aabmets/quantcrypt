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

from collections.abc import Callable
from quantcrypt.internal import constants as const
from .conftest import CryptoFilePaths, CLIMessages


class Test_Encrypt_Decrypt:
    algos = const.SupportedAlgos.armor_names(const.PQAType.KEM)

    @staticmethod
    def options(cfp: CryptoFilePaths) -> tuple[list[str], list[str]]:
        enc_opt = [
            '-p', cfp.public_key_fp,
            '-i', cfp.plaintext_fp,
            '-o', cfp.ciphertext_fp
        ]
        dec_opt = [
            '-s', cfp.secret_key_fp,
            '-i', cfp.ciphertext_fp,
            '-o', cfp.plaintext_fp + '2'
        ]
        return enc_opt, dec_opt

    @classmethod
    def test_encrypt_decrypt(cls, cfp_setup, cli_runner) -> None:
        print()
        for algorithm in cls.algos:
            print(f"Testing {algorithm} encryption and decryption in CLI")
            with cfp_setup(algorithm) as cfp:
                cli_runner("keygen", ['-N', algorithm])
                cls.flow(cfp, cli_runner)

    @classmethod
    def flow(cls, cfp: CryptoFilePaths, cli_runner: Callable) -> None:
        enc_opt, dec_opt = cls.options(cfp)

        cli_runner("encrypt", enc_opt, "n\n", CLIMessages.CANCELLED)
        cli_runner("encrypt", enc_opt + ['-D'], "y\n", CLIMessages.DRYRUN)
        cli_runner("encrypt", enc_opt, "y\n", CLIMessages.SUCCESS)
        cli_runner("encrypt", enc_opt, "y\nn\n", CLIMessages.CANCELLED)
        cli_runner("encrypt", enc_opt, "y\ny\n", CLIMessages.SUCCESS)
        cli_runner("encrypt", enc_opt + ['-N'], "", CLIMessages.ERROR)
        cli_runner("encrypt", enc_opt + ['-N', '-W'], "", CLIMessages.SUCCESS)

        cli_runner("decrypt", dec_opt, "n\n", CLIMessages.CANCELLED)
        cli_runner("decrypt", dec_opt + ['-D'], "y\n", CLIMessages.DRYRUN)
        cli_runner("decrypt", dec_opt, "y\n", CLIMessages.SUCCESS)
        cli_runner("decrypt", dec_opt, "y\nn\n", CLIMessages.CANCELLED)
        cli_runner("decrypt", dec_opt, "y\ny\n", CLIMessages.SUCCESS)
        cli_runner("decrypt", dec_opt + ['-N'], "", CLIMessages.ERROR)
        cli_runner("decrypt", dec_opt + ['-N', '-W'], "", CLIMessages.SUCCESS)

        with open(cfp.plaintext_fp + '2', 'rb') as file:
            assert cfp.ptf_data == file.read()
