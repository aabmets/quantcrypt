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

from quantcrypt.internal import utils, constants as const
from .conftest import CLIMessages


def test_remove(cli_runner, alt_tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(utils, "search_upwards", lambda *_: alt_tmp_path)
    for spec in const.SupportedAlgos:  # type: const.AlgoSpec
        (alt_tmp_path / spec.module_name(const.PQAVariant.REF)).touch()

    cli_runner("remove", ["mlkem512"], "n\n", CLIMessages.CANCELLED)
    cli_runner("remove", ["mlkem512"], "y\n", CLIMessages.SUCCESS)
    cli_runner("remove", ["mlkem512"], "y\n", CLIMessages.SUCCESS)
    cli_runner("remove", ["-D", "mlkem512"], "y\n", CLIMessages.DRYRUN)
    cli_runner("remove", ["-N", "fastsphincs"], "", CLIMessages.SUCCESS)
