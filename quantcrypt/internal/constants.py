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
from typing import Iterator
from dataclasses import dataclass


__all__ = [
    "ExtendedEnum",
    "PQAVariant",
    "PQAType",
    "PQAKeyType",
    "AlgoSpec",
    "SupportedAlgos",
    "SupportedVariants",
    "PQCleanRepoArchiveURL"
]


class ExtendedEnum(Enum):
    @classmethod
    def members(cls) -> list:
        return list(cls.__members__.values())

    @classmethod
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

    def armor_name(self) -> str:
        return self.name.replace('-', '').upper()

    def cdef_name(self, variant: PQAVariant) -> str:
        name = self.name.replace('-', '')
        return f"PQCLEAN_{name}_{variant.value}".upper()

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
    def iterate(cls) -> Iterator[AlgoSpec]:
        for value in vars(cls).values():
            if isinstance(value, AlgoSpec):
                yield value

    @classmethod
    def armor_names(cls, pqa_type: PQAType | None = None) -> list[str]:
        return [spec.armor_name() for spec in cls.iterate()
            if not pqa_type or spec.type == pqa_type]


KDFContext = b"quantcrypt"
KryptonFileSuffix = ".kptn"
SupportedVariants = [PQAVariant.REF]
AMDArches = ["x86_64", "amd64", "x86-64", "x64", "intel64"]
ARMArches = ["arm_8", "arm64", "aarch64", "armv8", "armv8-a"]
PQCleanRepoArchiveURL = "https://github.com/PQClean/PQClean/archive/448c71a8f590343e681d0d0cec94f29947b0ff18.zip"
