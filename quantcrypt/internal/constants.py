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
from dataclasses import dataclass
from enum import Enum


__all__ = [
    "PQCLEAN_REPO_URL",
    "PQAVariant",
    "PQAType",
    "AlgoSpec",
    "SupportedAlgos"
]


PQCLEAN_REPO_URL = "https://github.com/PQClean/PQClean/archive/448c71a8f590343e681d0d0cec94f29947b0ff18.zip"


class PQAVariant(Enum):
    """
    Available binaries of algorithms:
    * REF - Clean reference binaries for the x86_64 architecture.
    * OPT - Speed-optimized binaries for the x86_64 architecture.
    * ARM - Binaries for the aarch64 architecture.
    """
    REF = "clean"
    OPT = "avx2"
    ARM = "aarch64"


class PQAType(Enum):
    """
    Available types of algorithms:
    * KEM - Key Encapsulation Mechanism
    * DSS - Digital Signature Scheme
    """
    KEM = "kem"
    DSS = "dss"


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
