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
from quantcrypt.internal.pqa import kem_algos as kem
from .conftest import CryptoFilePaths, CLIMessages


def test_mlkem_512(cfp_setup, cli_runner):
    with cfp_setup(kem.MLKEM_512) as cfp:
        run_tests(cfp, cli_runner)


def test_mlkem_768(cfp_setup, cli_runner):
    with cfp_setup(kem.MLKEM_768) as cfp:
        run_tests(cfp, cli_runner)


def test_mlkem_1024(cfp_setup, cli_runner):
    with cfp_setup(kem.MLKEM_1024) as cfp:
        run_tests(cfp, cli_runner)


def run_tests(cfp: CryptoFilePaths, cli_runner: Callable):
    algo = cfp.algorithm
    print(f"Testing {algo} encryption and decryption in CLI")

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
    cli_runner("keygen", ['-N', algo])

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
