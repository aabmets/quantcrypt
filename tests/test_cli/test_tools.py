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
import string
import secrets
import itertools
from pathlib import Path
from quantcrypt.internal import constants as const
from quantcrypt.internal.cli import tools
from quantcrypt.internal.pqa.base_kem import BaseKEM
from quantcrypt.internal.pqa.base_dss import BaseDSS


def test_resolve_optional_file():
    path = tools.resolve_optional_file(
        optional_file=None,
        from_file=Path("asdfg.bin"),
        new_suffix=".txt"
    )
    assert path.name == "asdfg.txt"


def test_resolve_directory(tmp_path: Path):
    tmp_file = tmp_path / "file.txt"
    tmp_file.touch()

    with pytest.raises(SystemExit, match='1'):
        tools.resolve_directory(tmp_file.as_posix())

    sub_dir = tmp_path / "sub/dir"
    tools.resolve_directory(sub_dir.as_posix())
    assert sub_dir.exists()


def test_process_paths(tmp_path: Path):
    key_file = tmp_path / "key_file.txt"
    in_file = tmp_path / "in_file.txt"
    out_file = tmp_path / "out_file.txt"

    with pytest.raises(SystemExit, match='1'):
        tools.process_paths(
            key_file=key_file.as_posix(),
            in_file=in_file.as_posix(),
            out_file="",
            new_suffix=".suf"
        )

    key_file.touch()
    in_file.touch()
    out_file.touch()

    res = tools.process_paths(
        key_file=key_file.as_posix(),
        in_file=in_file.as_posix(),
        out_file=out_file.as_posix(),
        new_suffix=".suf"
    )
    assert isinstance(res, tools.CommandPaths)


def test_validate_armored_key():
    specs = const.SupportedAlgos
    key_types = const.PQAKeyType.members()
    key_content = secrets.token_hex(32)

    for spec, key_type in itertools.product(specs, key_types):  # type: const.AlgoSpec, const.PQAKeyType
        armor_name, key_type_name = spec.armor_name(), key_type.value
        header = f"-----BEGIN {armor_name} {key_type_name} KEY-----"
        footer = f"-----END {armor_name} {key_type_name} KEY-----"

        armored_key = f"{header}\n{key_content}\n{footer}"
        res = tools.validate_armored_key(armored_key, key_type, spec.type)
        assert res == armor_name

        with pytest.raises(SystemExit, match='1'):
            _armored_key = armored_key.replace(key_type_name, "KABOOM")
            tools.validate_armored_key(_armored_key, key_type, spec.type)

        with pytest.raises(SystemExit, match='1'):
            _key_type = const.PQAKeyType.PUBLIC.value
            if key_type == const.PQAKeyType.PUBLIC:
                _key_type = const.PQAKeyType.SECRET.value
            _armored_key = armored_key.replace(key_type_name, _key_type)
            tools.validate_armored_key(_armored_key, key_type, spec.type)

        with pytest.raises(SystemExit, match='1'):
            _armored_key = armored_key.replace(armor_name, "KABOOM")
            tools.validate_armored_key(_armored_key, key_type, spec.type)

        for _variable in [armor_name, key_type_name]:
            with pytest.raises(SystemExit, match='1'):
                _header = header.replace(_variable, "KABOOM")
                _armored_key = f"{_header}\n{key_content}\n{footer}"
                tools.validate_armored_key(_armored_key, key_type, spec.type)

            with pytest.raises(SystemExit, match='1'):
                _footer = footer.replace(_variable, "KABOOM")
                _armored_key = f"{header}\n{key_content}\n{_footer}"
                tools.validate_armored_key(_armored_key, key_type, spec.type)

        with pytest.raises(SystemExit, match='1'):
            _armored_key = armored_key.replace("BEGIN", "KABOOM")
            tools.validate_armored_key(_armored_key, key_type, spec.type)

        for bad_content in ['', ' ' * 100, *string.whitespace]:
            with pytest.raises(SystemExit, match='1'):
                _armored_key = armored_key.replace(key_content, bad_content)
                tools.validate_armored_key(_armored_key, key_type, spec.type)


def test_get_pqa_class():
    for armor_name in const.SupportedAlgos.armor_names():
        cls = tools.get_pqa_class(armor_name)
        assert issubclass(cls, (BaseKEM, BaseDSS))
        spec = cls.get_spec()
        assert isinstance(spec, const.AlgoSpec)
        assert spec.armor_name() == armor_name

    with pytest.raises(SystemExit, match='1'):
        tools.get_pqa_class("KABOOM")
