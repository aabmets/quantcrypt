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
from quantcrypt.internal.pqa import dss_algos as dss
from .conftest import CryptoFilePaths, CLIMessages


def test_mldsa_44(cfp_setup, cli_runner):
    with cfp_setup(dss.MLDSA_44) as cfp:
        run_tests(cfp, cli_runner)


def test_mldsa_65(cfp_setup, cli_runner):
    with cfp_setup(dss.MLDSA_65) as cfp:
        run_tests(cfp, cli_runner)


def test_mldsa_87(cfp_setup, cli_runner):
    with cfp_setup(dss.MLDSA_87) as cfp:
        run_tests(cfp, cli_runner)


def test_falcon_512(cfp_setup, cli_runner):
    with cfp_setup(dss.FALCON_512) as cfp:
        run_tests(cfp, cli_runner)


def test_falcon_1024(cfp_setup, cli_runner):
    with cfp_setup(dss.FALCON_1024) as cfp:
        run_tests(cfp, cli_runner)


def test_small_sphincs(cfp_setup, cli_runner):
    with cfp_setup(dss.SMALL_SPHINCS) as cfp:
        run_tests(cfp, cli_runner)


def test_fast_sphincs(cfp_setup, cli_runner):
    with cfp_setup(dss.FAST_SPHINCS) as cfp:
        run_tests(cfp, cli_runner)


def run_tests(cfp: CryptoFilePaths, cli_runner: Callable):
    algo = cfp.algorithm
    print(f"Testing {algo} signature verification in CLI")

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
    cli_runner("keygen", ['-N', algo])

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
