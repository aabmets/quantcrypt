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
from quantcrypt.internal.pqa.base_dss import BaseDSS


__all__ = [
    "MLDSA_44",
    "MLDSA_65",
    "MLDSA_87",
    "FALCON_512",
    "FALCON_1024",
    "FAST_SPHINCS",
    "SMALL_SPHINCS"
]


class MLDSA_44(BaseDSS):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the MLDSA_44 digital signature scheme algorithm
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


class MLDSA_65(BaseDSS):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the MLDSA_65 digital signature scheme algorithm
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


class MLDSA_87(BaseDSS):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the MLDSA_87 digital signature scheme algorithm
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


class FALCON_512(BaseDSS):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the FALCON_512 digital signature scheme algorithm
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


class FALCON_1024(BaseDSS):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the FALCON_1024 digital signature scheme algorithm
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


class FAST_SPHINCS(BaseDSS):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the FAST_SPHINCS digital signature scheme algorithm
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


class SMALL_SPHINCS(BaseDSS):  # NOSONAR
    @utils.input_validator()
    def __init__(self, variant: const.PQAVariant = None, *, allow_fallback: bool = True) -> None:
        """
        Initializes the SMALL_SPHINCS digital signature scheme algorithm
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
