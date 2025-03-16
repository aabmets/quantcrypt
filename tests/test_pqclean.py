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

import pytest
import platform
import itertools
from pathlib import Path
from unittest.mock import patch
from quantcrypt.internal import pqclean, constants as const


def _validate_common_filepaths(variant: const.PQAVariant) -> None:
    data = pqclean.get_common_filepaths(variant)
    assert Path(data[0]).is_dir()
    for cp in [Path(p) for p in data[1]]:
        assert cp.is_file()
        assert cp.suffix in ['.c', '.S', '.s']


def _check_windows_support(spec: const.AlgoSpec, variant: const.PQAVariant) -> None:
    with pytest.MonkeyPatch.context() as mpc:
        mpc.setattr(platform, "system", lambda: "Windows")
        mpc.setattr(platform, "machine", lambda: "x86_64")
        res1, res2 = pqclean.check_platform_support(spec, variant)
        if variant == const.PQAVariant.OPT_ARM:
            assert res1 is None and res2 is None
            return
        elif any(n in spec.class_name for n in ["FALCON", "SPHINCS"]):
            assert res1 is not None and res2 is not None
            return
        assert res1 is None and res2 is None


def _check_linux_support(spec: const.AlgoSpec, variant: const.PQAVariant) -> None:
    opt_amd, opt_arm = const.PQAVariant.OPT_AMD, const.PQAVariant.OPT_ARM
    for arch, _variant in [("x86_64", opt_amd), ("arm_8", opt_arm)]:
        with pytest.MonkeyPatch.context() as mpc:
            mpc.setattr(platform, "system", lambda: "Linux")
            mpc.setattr(platform, "machine", lambda: arch)  # NOSONAR
            res1, res2 = pqclean.check_platform_support(spec, variant)
            if _variant == variant:
                assert res1 is not None and res2 is not None
                return
            assert res1 is None and res2 is None


def test_pqclean_sources(alt_tmp_path):
    pqclean_dir = alt_tmp_path / "pqclean"
    pqclean_dir.mkdir(parents=True, exist_ok=True)

    with patch('internal.pqclean.utils.search_upwards') as mock:
        mock.side_effect = lambda *_, **__: pqclean_dir

        assert pqclean.check_sources_exist(pqclean_dir) is False
        pqclean.download_extract_pqclean(pqclean_dir)
        assert pqclean.check_sources_exist(pqclean_dir) is True

        for variant in const.PQAVariant.members():
            _validate_common_filepaths(variant)

        specs = const.SupportedAlgos
        variants = const.PQAVariant.members()

        for spec, variant in itertools.product(specs, variants):  # type: const.AlgoSpec, const.PQAVariant
            if variant == const.PQAVariant.REF:
                res1, res2 = pqclean.check_platform_support(spec, variant)
                assert res1 is not None and res2 is not None
                continue
            _check_windows_support(spec, variant)
            _check_linux_support(spec, variant)


def test_find_pqclean_dir(alt_tmp_path):
    nested_pqclean_dir = alt_tmp_path / "quantcrypt/pqclean"
    upper_pqclean_dir = alt_tmp_path / "pqclean"

    def _mocked_search_upwards(_, from_path = None):
        ret_path = nested_pqclean_dir
        if from_path is not None:
            ret_path = upper_pqclean_dir
        ret_path.mkdir(parents=True, exist_ok=True)
        return ret_path

    with patch('internal.pqclean.utils.search_upwards') as mock:
        mock.side_effect = _mocked_search_upwards

        pqclean_dir = pqclean.find_pqclean_dir(src_must_exist=False)
        assert pqclean_dir == nested_pqclean_dir

        with pytest.raises(RuntimeError):
            pqclean.find_pqclean_dir(src_must_exist=True)

        pqclean.download_extract_pqclean(upper_pqclean_dir)
        pqclean_dir = pqclean.find_pqclean_dir(src_must_exist=True)
        assert pqclean_dir == upper_pqclean_dir
