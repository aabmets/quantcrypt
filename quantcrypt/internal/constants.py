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
from enum import Enum
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
    "SupportedVariants",
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
    def values(cls) -> list:
        return [member.value for member in cls.members()]


class PQAVariant(ExtendedEnum):
    """
    Available binaries of algorithms:
    * REF - Clean reference binaries for the x86_64 architecture.
    * OPT - Speed-optimized binaries for the x86_64 architecture.
    * ARM - Binaries for the aarch64 architecture.
    """
    REF = "clean"
    OPT = "avx2"
    ARM = "aarch64"


class PQAType(ExtendedEnum):
    """
    Available types of PQ algorithms:
    * KEM - Key Encapsulation Mechanism
    * DSS - Digital Signature Scheme
    """
    KEM = "crypto_kem"
    DSS = "crypto_sign"


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
    name: str

    @classmethod
    def KEM(cls, name: str) -> AlgoSpec:  # NOSONAR
        return cls(type=PQAType.KEM, name=name)

    @classmethod
    def DSS(cls, name: str) -> AlgoSpec:  # NOSONAR
        return cls(type=PQAType.DSS, name=name)

    @cache
    def cdef_name(self, variant: PQAVariant) -> str:
        name = self.name.replace('-', '')
        return f"PQCLEAN_{name}_{variant.value}".upper()

    @cache
    def module_name(self, variant: PQAVariant) -> str:
        name = self.name.replace('-', '_')
        return f"{name}_{variant.value}".lower()


class SupportedAlgos:
    MLKEM_512 = AlgoSpec.KEM("ml-kem-512")
    MLKEM_768 = AlgoSpec.KEM("ml-kem-768")
    MLKEM_1024 = AlgoSpec.KEM("ml-kem-1024")
    MLDSA_44 = AlgoSpec.DSS("ml-dsa-44")
    MLDSA_65 = AlgoSpec.DSS("ml-dsa-65")
    MLDSA_87 = AlgoSpec.DSS("ml-dsa-87")
    FALCON_512 = AlgoSpec.DSS("falcon-512")
    FALCON_1024 = AlgoSpec.DSS("falcon-1024")
    FAST_SPHINCS = AlgoSpec.DSS("sphincs-shake-256f-simple")
    SMALL_SPHINCS = AlgoSpec.DSS("sphincs-shake-256s-simple")

    @classmethod
    @cache
    def items(cls) -> list[tuple[str, AlgoSpec]]:
        return [(k, v) for k, v in vars(cls).items() if isinstance(v, AlgoSpec)]

    @classmethod
    @cache
    def values(cls, pqa_type: PQAType | None = None) -> list[AlgoSpec]:
        return [
            v for v in vars(cls).values() if isinstance(v, AlgoSpec)
            and (not pqa_type or pqa_type == v.type)
        ]


KDFContext = b"quantcrypt"
KryptonFileSuffix = ".kptn"
SignatureFileSuffix = ".sig"
SupportedVariants = [PQAVariant.REF]
AMDArches = ["x86_64", "amd64", "x86-64", "x64", "intel64"]
ARMArches = ["arm_8", "arm64", "aarch64", "armv8", "armv8-a"]
PQCleanRepoArchiveURL = "https://github.com/PQClean/PQClean/archive/448c71a8f590343e681d0d0cec94f29947b0ff18.zip"
