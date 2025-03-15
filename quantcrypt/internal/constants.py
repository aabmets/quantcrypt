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
from itertools import product
from enum import Enum
from pathlib import Path
from functools import cache
from dataclasses import dataclass


__all__ = [
    "ExtendedEnum",
    "PQAVariant",
    "PQAType",
    "PQAKeyType",
    "AlgoSpec",
    "SupportedAlgos",
    "KDFContext",
    "KryptonFileSuffix",
    "AMDArches",
    "ARMArches",
    "PQCleanRepoArchiveURL"
]


class ExtendedEnum(Enum):
    @classmethod
    @cache
    def members(cls) -> list:
        return list(cls.__members__.values())

    @classmethod
    @cache
    def values(cls) -> list[str]:
        return [member.value for member in cls.members()]


class PQAVariant(ExtendedEnum):
    """
    Available binaries of algorithms:
    * REF - Clean reference binaries for the x86_64 architecture.
    * OPT - Speed-optimized binaries for the x86_64 architecture.
    * ARM - Binaries for the aarch64 architecture.
    """
    REF = "clean"
    OPT_AMD = "avx2"
    OPT_ARM = "aarch64"


class PQAType(ExtendedEnum):
    """
    Available types of PQ algorithms:
    * KEM - Key Encapsulation Mechanism
    * DSS - Digital Signature Scheme
    """
    KEM = "crypto_kem"
    DSS = "crypto_sign"
    _COM = "common"


class PQAKeyType(ExtendedEnum):
    """
    Available types of PQA keys:
    * PUBLIC - Public key
    * SECRET - Secret key
    """
    PUBLIC = "PUBLIC"
    SECRET = "SECRET"


@dataclass(frozen=True)
class AlgoSpec:
    type: PQAType
    src_subdir: Path
    pqclean_name: str
    class_name: str

    @classmethod
    def KEM(cls, class_name: str, pqclean_name: str) -> AlgoSpec:  # NOSONAR
        src_subdir = Path(PQAType.KEM.value, pqclean_name)
        return cls(
            type=PQAType.KEM,
            src_subdir=src_subdir,
            pqclean_name=pqclean_name,
            class_name=class_name
        )

    @classmethod
    def DSS(cls, class_name: str, pqclean_name: str) -> AlgoSpec:  # NOSONAR
        src_subdir = Path(PQAType.DSS.value, pqclean_name)
        return cls(
            type=PQAType.DSS,
            src_subdir=src_subdir,
            pqclean_name=pqclean_name,
            class_name=class_name
        )

    @cache
    def cdef_name(self, variant: PQAVariant) -> str:
        name = self.pqclean_name.replace('-', '')
        return f"PQCLEAN_{name}_{variant.value}".upper()

    @cache
    def module_name(self, variant: PQAVariant) -> str:
        name = self.pqclean_name.replace('-', '_')
        return f"{name}_{variant.value}".lower()

    @cache
    def armor_name(self) -> str:
        name = self.class_name.replace('_', '')
        return name.upper()  # case safety


class AlgoSpecsList(list):
    def pqclean_names(self: list[AlgoSpec]) -> list[str]:
        return [spec.pqclean_name for spec in self]

    def armor_names(self: list[AlgoSpec], pqa_type: PQAType | None = None) -> list[str]:
        return [
            spec.armor_name() for spec in self if
            not pqa_type or pqa_type == spec.type
        ]

    def filter(self, armor_names: list[str]) -> list[AlgoSpec]:
        return [
            spec for spec, name in product(self, armor_names)
            if spec.armor_name() == name.upper()
        ]


SupportedAlgos: AlgoSpecsList[AlgoSpec] = AlgoSpecsList([
    AlgoSpec.KEM(
        class_name="MLKEM_512",
        pqclean_name="ml-kem-512"
    ),
    AlgoSpec.KEM(
        class_name="MLKEM_768",
        pqclean_name="ml-kem-768"
    ),
    AlgoSpec.KEM(
        class_name="MLKEM_1024",
        pqclean_name="ml-kem-1024"
    ),
    AlgoSpec.DSS(
        class_name="MLDSA_44",
        pqclean_name="ml-dsa-44"
    ),
    AlgoSpec.DSS(
        class_name="MLDSA_65",
        pqclean_name="ml-dsa-65"
    ),
    AlgoSpec.DSS(
        class_name="MLDSA_87",
        pqclean_name="ml-dsa-87"
    ),
    AlgoSpec.DSS(
        class_name="FALCON_512",
        pqclean_name="falcon-512"
    ),
    AlgoSpec.DSS(
        class_name="FALCON_1024",
        pqclean_name="falcon-1024"
    ),
    AlgoSpec.DSS(
        class_name="FAST_SPHINCS",
        pqclean_name="sphincs-shake-256f-simple"
    ),
    AlgoSpec.DSS(
        class_name="SMALL_SPHINCS",
        pqclean_name="sphincs-shake-256s-simple"
    ),
])


KDFContext = b"quantcrypt"
SubprocTag = "<--quantcrypt-->"
KryptonFileSuffix = ".kptn"
SignatureFileSuffix = ".sig"
AMDArches = ["x86_64", "amd64", "x86-64", "x64", "intel64"]
ARMArches = ["arm_8", "arm64", "aarch64", "armv8", "armv8-a"]
PQCleanRepoArchiveURL = "https://github.com/PQClean/PQClean/archive/448c71a8f590343e681d0d0cec94f29947b0ff18.zip"
