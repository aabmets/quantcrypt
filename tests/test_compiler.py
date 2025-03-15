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
from quantcrypt.internal import utils, constants as const
from quantcrypt.internal.compiler import Compiler


def test_compiler_run(monkeypatch, alt_tmp_path):
    def _mocked_search_upwards(_path: Path | str):
        sub_path = alt_tmp_path / _path
        sub_path.mkdir(parents=True, exist_ok=True)
        return sub_path

    monkeypatch.setattr(utils, "search_upwards", _mocked_search_upwards)

    bin_path = alt_tmp_path / "bin"
    old_file = bin_path / "old_file"
    old_folder = bin_path / "old_folder"
    old_folder.mkdir(parents=True)
    old_file.touch()

    sup_alg_len = len(const.SupportedAlgos)
    variant_len = len(const.PQAVariant.values())
    variants = [const.PQAVariant.REF]

    rejected = Compiler().run(variants, [])
    assert len(rejected) == (sup_alg_len * variant_len)
    assert old_file.exists() and old_folder.exists()
    assert len(list(bin_path.iterdir())) == 2

    algos = const.SupportedAlgos.filter(["MLKEM512", "MLDSA44"])
    rejected = Compiler().run(variants, algos)
    assert len(rejected) == (sup_alg_len * variant_len - 2)
    assert not old_file.exists() and not old_folder.exists()
    assert len(list(bin_path.iterdir())) == 2
