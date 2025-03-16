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

from pathlib import Path
from collections.abc import Callable
from quantcrypt.internal import utils
from quantcrypt.internal.pqa import dss_algos as dss
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
	print(f"Testing {algo} key generation in CLI")

	public_key = Path(cfp.public_key_fp)
	secret_key = Path(cfp.secret_key_fp)

	assert not public_key.exists()
	assert not secret_key.exists()

	cli_runner("keygen", [algo], "n\n", CLIMessages.CANCELLED)
	cli_runner("keygen", ["-D", algo], "y\n", CLIMessages.DRYRUN)

	assert not public_key.exists()
	assert not secret_key.exists()

	cli_runner("keygen", [algo], "y\n", CLIMessages.SUCCESS)

	assert public_key.exists()
	assert secret_key.exists()

	pkf_digest_1 = utils.sha3_digest_file(public_key)
	skf_digest_1 = utils.sha3_digest_file(secret_key)

	cli_runner("keygen", [algo], "y\nn\n", CLIMessages.CANCELLED)
	cli_runner("keygen", [algo], "y\ny\n", CLIMessages.SUCCESS)

	cli_runner("keygen", ["-N", algo], "", CLIMessages.ERROR)
	cli_runner("keygen", ["-N", "-W", algo], "", CLIMessages.SUCCESS)

	cli_runner("keygen", ["-i", "!", algo], "", CLIMessages.ERROR)
	cli_runner("keygen", ["-i", "x" * 16, algo], "", CLIMessages.ERROR)
	cli_runner("keygen", ["-i", "asdfg", algo], "y\n", CLIMessages.SUCCESS)

	public_key = public_key.with_name(f"asdfg-{public_key.name}")
	secret_key = secret_key.with_name(f"asdfg-{secret_key.name}")

	pkf_digest_2 = utils.sha3_digest_file(public_key)
	skf_digest_2 = utils.sha3_digest_file(secret_key)

	assert pkf_digest_1 != pkf_digest_2
	assert skf_digest_1 != skf_digest_2
