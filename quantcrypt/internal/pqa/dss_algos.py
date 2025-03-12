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
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the MLDSA_44 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for the
			current platform *(any-select mode)*. This is a fatal error which
			requires either the library to be reinstalled or the binaries to be
			recompiled, because all platforms should have CLEAN binaries available.
		"""
		super().__init__(variant)


class MLDSA_65(BaseDSS):  # NOSONAR
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the MLDSA_65 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for the
			current platform *(any-select mode)*. This is a fatal error which
			requires either the library to be reinstalled or the binaries to be
			recompiled, because all platforms should have CLEAN binaries available.
		"""
		super().__init__(variant)


class MLDSA_87(BaseDSS):  # NOSONAR
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the MLDSA_87 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for the
			current platform *(any-select mode)*. This is a fatal error which
			requires either the library to be reinstalled or the binaries to be
			recompiled, because all platforms should have CLEAN binaries available.
		"""
		super().__init__(variant)


class FALCON_512(BaseDSS):  # NOSONAR
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the FALCON_512 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for the
			current platform *(any-select mode)*. This is a fatal error which
			requires either the library to be reinstalled or the binaries to be
			recompiled, because all platforms should have CLEAN binaries available.
		"""
		super().__init__(variant)


class FALCON_1024(BaseDSS):  # NOSONAR
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the FALCON_1024 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for the
			current platform *(any-select mode)*. This is a fatal error which
			requires either the library to be reinstalled or the binaries to be
			recompiled, because all platforms should have CLEAN binaries available.
		"""
		super().__init__(variant)


class FAST_SPHINCS(BaseDSS):  # NOSONAR
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the FAST_SPHINCS instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for the
			current platform *(any-select mode)*. This is a fatal error which
			requires either the library to be reinstalled or the binaries to be
			recompiled, because all platforms should have CLEAN binaries available.
		"""
		super().__init__(variant)


class SMALL_SPHINCS(BaseDSS):  # NOSONAR
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the SMALL_SPHINCS instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for the
			current platform *(any-select mode)*. This is a fatal error which
			requires either the library to be reinstalled or the binaries to be
			recompiled, because all platforms should have CLEAN binaries available.
		"""
		super().__init__(variant)
