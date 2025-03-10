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

from enum import Enum


__all__ = [
    "PQCLEAN_REPO_URL",
    "PQAVariant",
    "PQAType",
    "AlgoSpecBase",
    "AlgoSpecKEM",
    "AlgoSpecDSS",
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


class AlgoSpecBase:
    def __init__(self, pqa_type: PQAType, pqa_name: str) -> None:
        self.type = pqa_type
        self.name = pqa_name


class AlgoSpecKEM(AlgoSpecBase):
    def __init__(self, name: str) -> None:
        super().__init__(PQAType.KEM, name)


class AlgoSpecDSS(AlgoSpecBase):
    def __init__(self, name: str) -> None:
        super().__init__(PQAType.DSS, name)


class SupportedAlgos:
    MLKEM_512 = AlgoSpecKEM("ml-kem-512")
    MLKEM_768 = AlgoSpecKEM("ml-kem-768")
    MLKEM_1024 = AlgoSpecKEM("ml-kem-1024")
    MLDSA_44 = AlgoSpecDSS("ml-dsa-44")
    MLDSA_65 = AlgoSpecDSS("ml-dsa-65")
    MLDSA_87 = AlgoSpecDSS("ml-dsa-87")
    FALCON_512 = AlgoSpecDSS("falcon-512")
    FALCON_1024 = AlgoSpecDSS("falcon-1024")
    FAST_SPHINCS = AlgoSpecDSS("sphincs-shake-256f-simple")
    SMALL_SPHINCS = AlgoSpecDSS("sphincs-shake-256s-simple")
