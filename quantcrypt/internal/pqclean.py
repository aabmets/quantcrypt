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
import zipfile
import requests
import typing as t
import platform
from pydantic import BaseModel
from pathlib import Path
from functools import lru_cache
from quantcrypt.internal import constants as const
from quantcrypt.internal import utils


__all__ = [
    "filter_archive_contents",
    "download_extract_pqclean",
    "get_common_filepaths",
    "PQASupportedPlatform",
    "PQAImplementation",
    "PQAMetaData",
    "read_algo_metadata",
    "check_platform_support"
]


def filter_archive_contents(members: t.List[zipfile.ZipInfo]) -> t.List[t.Tuple[zipfile.ZipInfo, Path]]:
    supported_algos = [spec.name for spec in const.SupportedAlgos.iterate()]
    accepted_dirs = ["common", "crypto_kem", "crypto_sign"]
    filtered_members = []

    for member in members:
        if member.is_dir():
            continue
        match = re.search(r"/(.+)", member.filename)
        if not match:
            continue
        file_path = Path(match.group(1))
        parts = file_path.parts
        if parts[0] not in accepted_dirs:
            continue
        elif parts[0] != "common" and parts[1] not in supported_algos:
            continue
        filtered_members.append((member, file_path))

    return filtered_members


def download_extract_pqclean() -> None:
    pqclean = utils.search_upwards('pqclean')
    zip_path = pqclean / "temp.zip"

    response = requests.get(const.PQCleanRepoArchiveURL, stream=True)
    response.raise_for_status()

    with open(zip_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member, file_path in filter_archive_contents(zip_ref.infolist()):
            full_path = pqclean / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with full_path.open("wb") as f:
                f.write(zip_ref.read(member))

    zip_path.unlink()


def get_common_filepaths(self) -> tuple[str, list[str]]:
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

    if self.variant == const.PQAVariant.OPT:
        common.extend(keccak4x)
    elif self.variant == const.PQAVariant.ARM:
        common.extend(keccak2x)

    return path.as_posix(), common


class PQASupportedPlatform(BaseModel):
    architecture: t.Literal["x86_64", "arm_8"]
    required_flags: t.Optional[t.List[str]] = None
    operating_systems: t.Optional[t.List[str]] = None


class PQAImplementation(BaseModel):
    name: str
    supported_platforms: t.Optional[t.List[PQASupportedPlatform]] = None


class PQAMetaData(BaseModel):
    implementations: t.List[PQAImplementation]

    def filter(self, variant: const.PQAVariant) -> t.Optional[PQAImplementation]:
        impl = [i for i in self.implementations if i.name == variant.value]
        return impl[0] if impl else None


@lru_cache
def read_algo_metadata(spec: const.AlgoSpec) -> PQAMetaData:
    pqclean = utils.search_upwards('pqclean')
    algo_dir = pqclean / f"{spec.type.value}/{spec.name}"
    with (algo_dir / "META.yml").open('r') as file:
        data: dict = yaml.full_load(file)
    return PQAMetaData(**data)


def check_platform_support(
        spec: const.AlgoSpec,
        variant: const.PQAVariant
) -> t.Optional[t.Tuple[Path, t.List[str]]]:
    required_flags: t.List[str] = []
    meta = read_algo_metadata(spec)
    impl = meta.filter(variant)

    if not impl:
        return None
    elif impl.supported_platforms:
        supported_arches = ["x86_64", "amd64", "x86-64", "x64", "intel64"]
        if impl.name == const.PQAVariant.ARM.value:
            supported_arches = ["arm_8", "arm64", "aarch64", "armv8", "armv8-a"]
        found_platform: t.Optional[PQASupportedPlatform] = None
        for spf in impl.supported_platforms:
            if platform.machine().lower() in supported_arches:
                found_platform = spf
                break
        if not found_platform:
            return None
        if found_platform.operating_systems:
            found_opsys: t.Optional[str] = None
            for pos in found_platform.operating_systems:
                if platform.system().lower() == pos.lower():
                    found_opsys = pos
                    break
            if not found_opsys:
                return None
        if found_platform.required_flags:
            required_flags = found_platform.required_flags

    pqclean = utils.search_upwards('pqclean')
    variant_path = pqclean / f"{spec.type.value}/{spec.name}/{variant.value}"
    if variant_path.exists():
        return variant_path, required_flags
    return None
