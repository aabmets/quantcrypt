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


def test_extended_enum():
    class TestEnum(const.ExtendedEnum):
        FIRST = "asdfg"
        SECOND = "qwerty"

    assert TestEnum.members() == [
        TestEnum.FIRST,
        TestEnum.SECOND,
    ]
    assert TestEnum.values() == [
        TestEnum.FIRST.value,
        TestEnum.SECOND.value,
    ]
    assert TestEnum.FIRST.value == "asdfg"
    assert TestEnum.SECOND.value == "qwerty"


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
    assert const.PQAType.members() == [
        const.PQAType.KEM,
        const.PQAType.DSS
    ]
    assert const.PQAType.values() == [
        const.PQAType.KEM.value,
        const.PQAType.DSS.value
    ]
    assert const.PQAType.KEM.value == "crypto_kem"
    assert const.PQAType.DSS.value == "crypto_sign"


def test_pqa_key_type():
    assert const.PQAKeyType.members() == [
        const.PQAKeyType.PUBLIC,
        const.PQAKeyType.SECRET
    ]
    assert const.PQAKeyType.values() == [
        const.PQAKeyType.PUBLIC.value,
        const.PQAKeyType.SECRET.value
    ]
    assert const.PQAKeyType.PUBLIC.value == "PUBLIC"
    assert const.PQAKeyType.SECRET.value == "SECRET"


def test_algo_spec():
    spec_types = [
        (const.AlgoSpec.KEM, const.PQAType.KEM),
        (const.AlgoSpec.DSS, const.PQAType.DSS),
    ]
    for algo_spec, pqa_type in spec_types:
        spec = algo_spec("asdfg-1234")
        assert isinstance(spec, const.AlgoSpec)
        assert spec.type == pqa_type
        assert spec.armor_name() == "ASDFG1234"

        assert spec.cdef_name(const.PQAVariant.REF) == "PQCLEAN_ASDFG1234_CLEAN"
        assert spec.cdef_name(const.PQAVariant.OPT) == "PQCLEAN_ASDFG1234_AVX2"
        assert spec.cdef_name(const.PQAVariant.ARM) == "PQCLEAN_ASDFG1234_AARCH64"

        assert spec.module_name(const.PQAVariant.REF) == "asdfg_1234_clean"
        assert spec.module_name(const.PQAVariant.OPT) == "asdfg_1234_avx2"
        assert spec.module_name(const.PQAVariant.ARM) == "asdfg_1234_aarch64"


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
