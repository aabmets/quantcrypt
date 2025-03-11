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

import inspect
import requests
from quantcrypt.internal import constants as const


def test_pqa_variant():
    assert const.PQAVariant.members() == [
        const.PQAVariant.REF,
        const.PQAVariant.OPT,
        const.PQAVariant.ARM
    ]
    assert const.PQAVariant.values() == [
        const.PQAVariant.REF.value,
        const.PQAVariant.OPT.value,
        const.PQAVariant.ARM.value
    ]
    assert const.PQAVariant.REF.value == "clean"
    assert const.PQAVariant.OPT.value == "avx2"
    assert const.PQAVariant.ARM.value == "aarch64"


def test_pqa_type():
    assert const.PQAType.KEM.value == "crypto_kem"
    assert const.PQAType.DSS.value == "crypto_sign"


def test_algo_spec():
    spec_types = [
        (const.AlgoSpec.KEM, const.PQAType.KEM),
        (const.AlgoSpec.DSS, const.PQAType.DSS),
    ]
    for algo_spec, pqa_type in spec_types:
        spec = algo_spec("asdfg")
        assert isinstance(spec, const.AlgoSpec)
        assert spec.type == pqa_type

        expected = f"PQCLEAN_ASDFG_CLEAN"
        assert spec.cdef_name(const.PQAVariant.REF) == expected
        expected = f"PQCLEAN_ASDFG_AVX2"
        assert spec.cdef_name(const.PQAVariant.OPT) == expected
        expected = f"PQCLEAN_ASDFG_AARCH64"
        assert spec.cdef_name(const.PQAVariant.ARM) == expected

        expected = f"asdfg_clean"
        assert spec.module_name(const.PQAVariant.REF) == expected
        expected = f"asdfg_avx2"
        assert spec.module_name(const.PQAVariant.OPT) == expected
        expected = f"asdfg_aarch64"
        assert spec.module_name(const.PQAVariant.ARM) == expected


def test_supported_algos():
    for k, v in vars(const.SupportedAlgos).items():
        if any([
            k.startswith("__"),
            isinstance(v, classmethod),
            isinstance(v, staticmethod),
            isinstance(v, property),
            inspect.ismethod(v)
        ]):
            continue
        assert isinstance(v, const.AlgoSpec)

    for item in const.SupportedAlgos.iterate():
        assert isinstance(item, const.AlgoSpec)


def test_pqclean_repo_archive_url():
    url = const.PQCleanRepoArchiveURL
    res = requests.head(url)
    if res.status_code == 302:
        url = res.headers["location"]
        res = requests.head(url)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
