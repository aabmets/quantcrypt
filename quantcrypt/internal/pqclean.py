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

from __future__ import annotations
import re
import yaml
import requests
import platform
from typing import Literal
from zipfile import ZipFile, ZipInfo
from pathlib import Path
from pydantic import BaseModel
from functools import cache
from itertools import product
from quantcrypt.internal import constants as const
from quantcrypt.internal import utils


__all__ = [
    "check_sources_exist",
    "filter_archive_contents",
    "download_extract_pqclean",
    "get_common_filepaths",
    "PQASupportedPlatform",
    "PQAImplementation",
    "PQAMetaData",
    "read_algo_metadata",
    "check_opsys_support",
    "check_arch_support",
    "check_platform_support"
]


def check_sources_exist() -> bool:
    pqclean = utils.search_upwards('pqclean')
    check_dirs: list[bool] = []
    specs = const.SupportedAlgos
    variants: list[str] = const.PQAVariant.values()
    for spec, variant in product(specs, variants):
        path = pqclean / spec.src_subdir / variant
        check_dirs.append(path.exists())
    return all(check_dirs)


def filter_archive_contents(members: list[ZipInfo]) -> list[tuple[ZipInfo, Path]]:
    supported_algos = const.SupportedAlgos.pqclean_names()
    accepted_dirs = const.PQAType.values()
    filtered_members = []

    for member in members:
        if member.is_dir():
            continue
        match = re.search(r"/(.+)", member.filename)
        if not match:  # pragma: no cover
            continue
        file_path = Path(match.group(1))
        parts = file_path.parts
        if parts[0] not in accepted_dirs:
            continue
        elif parts[0] != "common" and parts[1] not in supported_algos:
            continue  # NOSONAR
        filtered_members.append((member, file_path))

    return filtered_members


def download_extract_pqclean() -> None:
    pqclean = utils.search_upwards('pqclean')
    zip_path = pqclean / "temp.zip"

    response = requests.get(const.PQCleanRepoArchiveURL, stream=True)
    response.raise_for_status()

    with open(zip_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:  # pragma: no branch
                f.write(chunk)

    with ZipFile(zip_path, 'r') as zip_ref:
        for member, file_path in filter_archive_contents(zip_ref.infolist()):
            full_path = pqclean / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with full_path.open("wb") as f:
                f.write(zip_ref.read(member))

    zip_path.unlink()


@cache
def get_common_filepaths(variant: const.PQAVariant) -> tuple[str, list[str]]:
    path = utils.search_upwards("pqclean/common")
    common, keccak2x, keccak4x = list(), list(), list()

    for file in path.rglob("**/*"):
        if file.is_file() and file.suffix == '.c':
            file = file.as_posix()
            files_list = common
            if 'keccak2x' in file:
                files_list = keccak2x
            elif 'keccak4x' in file:
                files_list = keccak4x
            files_list.append(file)

    if variant == const.PQAVariant.OPT_AMD:
        common.extend(keccak4x)
    elif variant == const.PQAVariant.OPT_ARM:
        common.extend(keccak2x)

    return path.as_posix(), common


class PQASupportedPlatform(BaseModel):
    architecture: Literal["x86_64", "arm_8"]
    required_flags: list[str] | None = None
    operating_systems: list[str] | None = None


class PQAImplementation(BaseModel):
    name: str
    supported_platforms: list[PQASupportedPlatform] | None = None


class PQAMetaData(BaseModel):
    implementations: list[PQAImplementation]

    def filter(self, variant: const.PQAVariant) -> PQAImplementation | None:
        impl = [i for i in self.implementations if i.name == variant.value]
        return impl[0] if impl else None


@cache
def read_algo_metadata(spec: const.AlgoSpec) -> PQAMetaData:
    pqclean = utils.search_upwards('pqclean')
    meta_file = pqclean / spec.src_subdir / "META.yml"
    with meta_file.open('r') as file:
        data: dict = yaml.full_load(file)
    return PQAMetaData(**data)


def check_opsys_support(spf: PQASupportedPlatform) -> str | None:
    for opsys in spf.operating_systems:
        if platform.system().lower() == opsys.lower():
            return opsys
    return None


def check_arch_support(impl: PQAImplementation) -> PQASupportedPlatform | None:
    supported_arches = const.AMDArches
    if impl.name == const.PQAVariant.OPT_ARM.value:
        supported_arches = const.ARMArches
    for spf in impl.supported_platforms:
        if platform.machine().lower() in supported_arches:
            return spf
    return None


def check_platform_support(
        spec: const.AlgoSpec,
        variant: const.PQAVariant
) -> tuple[Path, list[str]] | tuple[None, None]:
    required_flags: list[str] = []
    meta = read_algo_metadata(spec)
    impl = meta.filter(variant)

    if not impl:  # pragma: no cover
        return None, None
    elif impl.supported_platforms:
        spf = check_arch_support(impl)
        if not spf:
            return None, None
        if spf.operating_systems:
            opsys = check_opsys_support(spf)
            if not opsys:
                return None, None
        if spf.required_flags:  # pragma: no branch
            required_flags = spf.required_flags

    pqclean = utils.search_upwards('pqclean')
    variant_path = pqclean / spec.src_subdir / variant.value
    if variant_path.exists():  # pragma: no branch
        return variant_path, required_flags
    return None, None  # pragma: no cover
