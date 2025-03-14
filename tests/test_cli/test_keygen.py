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
from quantcrypt.internal import utils, constants as const
from .conftest import CryptoFilePaths, CLIMessages


class Test_Keygen:
	algos = const.SupportedAlgos.armor_names()

	@classmethod
	def test_keygen(cls, cfp_setup, cli_runner) -> None:
		print()
		for algorithm in cls.algos:
			print(f"Testing {algorithm} key generation in CLI")
			with cfp_setup(algorithm) as cfp:
				cls.flow(algorithm, cfp, cli_runner)

	@staticmethod
	def flow(algorithm: str, cfp: CryptoFilePaths, cli_runner: Callable) -> None:
		public_key = Path(cfp.public_key_fp)
		secret_key = Path(cfp.secret_key_fp)

		assert not public_key.exists()
		assert not secret_key.exists()

		cli_runner("keygen", [algorithm], "n\n", CLIMessages.CANCELLED)
		cli_runner("keygen", ["-D", algorithm], "y\n", CLIMessages.DRYRUN)

		assert not public_key.exists()
		assert not secret_key.exists()

		cli_runner("keygen", [algorithm], "y\n", CLIMessages.SUCCESS)

		assert public_key.exists()
		assert secret_key.exists()

		pkf_digest_1 = utils.sha3_digest_file(public_key)
		skf_digest_1 = utils.sha3_digest_file(secret_key)

		cli_runner("keygen", [algorithm], "y\nn\n", CLIMessages.CANCELLED)
		cli_runner("keygen", [algorithm], "y\ny\n", CLIMessages.SUCCESS)

		cli_runner("keygen", ["-N", algorithm], "", CLIMessages.ERROR)
		cli_runner("keygen", ["-N", "-W", algorithm], "", CLIMessages.SUCCESS)

		cli_runner("keygen", ["-i", "!", algorithm], "", CLIMessages.ERROR)
		cli_runner("keygen", ["-i", "x" * 16, algorithm], "", CLIMessages.ERROR)
		cli_runner("keygen", ["-i", "asdfg", algorithm], "y\n", CLIMessages.SUCCESS)

		public_key = public_key.with_name(f"asdfg-{public_key.name}")
		secret_key = secret_key.with_name(f"asdfg-{secret_key.name}")

		pkf_digest_2 = utils.sha3_digest_file(public_key)
		skf_digest_2 = utils.sha3_digest_file(secret_key)

		assert pkf_digest_1 != pkf_digest_2
		assert skf_digest_1 != skf_digest_2
