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

import re
from pathlib import Path
from typing import Type
from dotmap import DotMap
from dataclasses import dataclass
from quantcrypt.internal import utils, constants as const
from quantcrypt.internal.cli import console
from quantcrypt.internal.pqa import dss_algos
from quantcrypt.internal.pqa import kem_algos
from quantcrypt.internal.pqa.base_kem import BaseKEM
from quantcrypt.internal.pqa.base_dss import BaseDSS


__all__ = [
    "CommandPaths",
    "resolve_optional_file",
    "resolve_directory",
    "process_paths",
    "validate_armored_key",
    "get_pqa_class"
]


@dataclass
class CommandPaths:
    key_file: Path
    in_file: Path
    out_file: Path
    sig_file: Path


def resolve_optional_file(
        optional_file: str | None,
        from_file: Path,
        new_suffix: str
) -> Path:
    if not optional_file:
        return from_file.with_suffix(new_suffix)
    return utils.resolve_relpath(optional_file)


def resolve_directory(dir_arg: str | None) -> Path:
    target_dir = utils.resolve_relpath(dir_arg)
    if target_dir.is_file():
        msg = f"The provided path is not a directory: [italic tan]{target_dir}"
        console.raise_error(msg)
    elif not target_dir.exists():
        target_dir.mkdir(parents=True)
    return target_dir


def process_paths(
        key_file: str,
        in_file: str,
        out_file: str,
        new_suffix: str,
        out_file_must_exist: bool = False
) -> CommandPaths:
    _key_file = utils.resolve_relpath(key_file)
    _in_file = utils.resolve_relpath(in_file)
    _out_file = resolve_optional_file(
        optional_file=out_file,
        from_file=_in_file,
        new_suffix=new_suffix
    )
    files = [_key_file, _in_file]
    if out_file_must_exist:
        files.append(_out_file)

    for file in files:
        if not file.is_file():
            console.raise_error(
                f"File [italic sky_blue2]{file.name}[/] does not "
                f"exist in directory:\n[italic tan]{file.parent}"
            )
    return CommandPaths(
        key_file=_key_file,
        in_file=_in_file,
        out_file=_out_file,
        sig_file=_out_file
    )


def validate_armored_key(
        armored_key: str,
        key_type: const.PQAKeyType,
        pqa_type: const.PQAType
) -> str:
    header_pattern = r"^-----BEGIN (?P<hdr_name>\w+) (?P<hdr_type>[A-Z_]+) KEY-----\n"
    footer_pattern = r"\n-----END (?P<ftr_name>\w+) (?P<ftr_type>[A-Z_]+) KEY-----$"
    full_pattern = header_pattern + r"(?P<content>.+)" + footer_pattern

    full_match = re.match(full_pattern, armored_key, re.DOTALL)
    fm = DotMap(full_match.groupdict()) if full_match else None

    if not fm or not fm.content or not fm.content.strip():
        console.raise_error("The armored key is corrupted.")
    elif fm.hdr_name != fm.ftr_name or fm.hdr_type != fm.ftr_type:
        console.raise_error("The envelope of the armored key is corrupted.")
    elif fm.hdr_name not in const.SupportedAlgos.armor_names(pqa_type):
        console.raise_error(f"Unsupported algorithm {fm.hdr_name} in armored key header.")
    elif fm.hdr_type not in const.PQAKeyType.values():
        console.raise_error(f"Unsupported key type {fm.hdr_type} in armored key header.")
    elif fm.hdr_type != key_type.value:
        console.raise_error(
            f"Expected a {key_type.value.lower()} key, but "
            f"received a {fm.hdr_type.lower()} key instead."
        )
    return fm.hdr_name  # NOSONAR


def get_pqa_class(armor_name: str) -> Type[BaseKEM | BaseDSS]:
    for spec in const.SupportedAlgos:
        if spec.armor_name() == armor_name.upper():
            is_kem = spec.type == const.PQAType.KEM
            module = kem_algos if is_kem else dss_algos
            return getattr(module, spec.class_name)
    console.raise_error(f"Algorithm name '{armor_name}' does not map to any supported PQA class.")
    raise  # NOSONAR
