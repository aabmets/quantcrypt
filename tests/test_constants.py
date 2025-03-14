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

import requests
from pathlib import Path
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
        const.PQAVariant.OPT_AMD,
        const.PQAVariant.OPT_ARM
    ]
    assert const.PQAVariant.values() == [
        const.PQAVariant.REF.value,
        const.PQAVariant.OPT_AMD.value,
        const.PQAVariant.OPT_ARM.value
    ]
    assert const.PQAVariant.REF.value == "clean"
    assert const.PQAVariant.OPT_AMD.value == "avx2"
    assert const.PQAVariant.OPT_ARM.value == "aarch64"


def test_pqa_type():
    assert const.PQAType.members() == [
        const.PQAType.KEM,
        const.PQAType.DSS,
        const.PQAType._COM
    ]
    assert const.PQAType.values() == [
        const.PQAType.KEM.value,
        const.PQAType.DSS.value,
        const.PQAType._COM.value
    ]
    assert const.PQAType.KEM.value == "crypto_kem"
    assert const.PQAType.DSS.value == "crypto_sign"
    assert const.PQAType._COM.value == "common"


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
        class_name, pqclean_name = "ASDFG_1234", "as-dfg-1234"
        spec: const.AlgoSpec = algo_spec(
            class_name=class_name,
            pqclean_name=pqclean_name
        )
        assert isinstance(spec, const.AlgoSpec)
        assert spec.src_subdir == Path(pqa_type.value, pqclean_name)
        assert spec.pqclean_name == pqclean_name
        assert spec.class_name == class_name
        assert spec.type == pqa_type
        assert spec.armor_name() == "ASDFG1234"

        assert spec.cdef_name(const.PQAVariant.REF) == "PQCLEAN_ASDFG1234_CLEAN"
        assert spec.cdef_name(const.PQAVariant.OPT_AMD) == "PQCLEAN_ASDFG1234_AVX2"
        assert spec.cdef_name(const.PQAVariant.OPT_ARM) == "PQCLEAN_ASDFG1234_AARCH64"

        assert spec.module_name(const.PQAVariant.REF) == "as_dfg_1234_clean"
        assert spec.module_name(const.PQAVariant.OPT_AMD) == "as_dfg_1234_avx2"
        assert spec.module_name(const.PQAVariant.OPT_ARM) == "as_dfg_1234_aarch64"


def test_supported_algos():
    assert isinstance(const.SupportedAlgos, list)

    for item in const.SupportedAlgos:
        assert isinstance(item, const.AlgoSpec)

    for item in const.SupportedAlgos.pqclean_names():
        assert isinstance(item, str)

    for item in const.SupportedAlgos.armor_names():
        assert isinstance(item, str)

    specs = const.SupportedAlgos.filter(["asdfg1234"])
    assert specs == []

    armor_names = ["MLKEM1024", "MLDSA87"]
    specs = const.SupportedAlgos.filter(armor_names)
    assert isinstance(specs, list) and len(specs) == 2
    for spec in specs:
        assert spec.armor_name() in armor_names
        assert isinstance(spec, const.AlgoSpec)

    for pqa_type in const.PQAType.members():  # type: const.PQAType
        for item in const.SupportedAlgos.armor_names(pqa_type):
            assert isinstance(item, str)


def test_pqclean_repo_archive_url():
    url = const.PQCleanRepoArchiveURL
    res = requests.head(url)
    if res.status_code == 302:
        url = res.headers["location"]
        res = requests.head(url)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
