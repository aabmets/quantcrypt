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

from quantcrypt.internal import utils, constants as const
from quantcrypt.internal.pqa.base_kem import BaseKEM


__all__ = ["MLKEM_512", "MLKEM_768", "MLKEM_1024"]


class MLKEM_512(BaseKEM):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the MLKEM_512 key encapsulation mechanism algorithm
        instance with compiled C extension binaries.

        :param variant: Which compiled binary to use underneath.
            When variant is None *(auto-select mode)*, QuantCrypt will first try to use
            platform-optimized binaries. If it fails to do so and fallback is allowed,
            it will then try to fall back to using clean reference binaries.
        :param allow_fallback: Allow falling back to using clean reference binaries when
            QuantCrypt has failed to import platform-optimized binaries. Defaults to True.
        :raises - ImportFailedError: When QuantCrypt has failed to fall back to using clean
            reference binaries, either because they are missing or fallback was not permitted.
        """
        super().__init__(variant, allow_fallback)


class MLKEM_768(BaseKEM):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the MLKEM_512 key encapsulation mechanism algorithm
        instance with compiled C extension binaries.

        :param variant: Which compiled binary to use underneath.
            When variant is None *(auto-select mode)*, QuantCrypt will first try to use
            platform-optimized binaries. If it fails to do so and fallback is allowed,
            it will then try to fall back to using clean reference binaries.
        :param allow_fallback: Allow falling back to using clean reference binaries when
            QuantCrypt has failed to import platform-optimized binaries. Defaults to True.
        :raises - ImportFailedError: When QuantCrypt has failed to fall back to using clean
            reference binaries, either because they are missing or fallback was not permitted.
        """
        super().__init__(variant, allow_fallback)


class MLKEM_1024(BaseKEM):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the MLKEM_512 key encapsulation mechanism algorithm
        instance with compiled C extension binaries.

        :param variant: Which compiled binary to use underneath.
            When variant is None *(auto-select mode)*, QuantCrypt will first try to use
            platform-optimized binaries. If it fails to do so and fallback is allowed,
            it will then try to fall back to using clean reference binaries.
        :param allow_fallback: Allow falling back to using clean reference binaries when
            QuantCrypt has failed to import platform-optimized binaries. Defaults to True.
        :raises - ImportFailedError: When QuantCrypt has failed to fall back to using clean
            reference binaries, either because they are missing or fallback was not permitted.
        """
        super().__init__(variant, allow_fallback)
