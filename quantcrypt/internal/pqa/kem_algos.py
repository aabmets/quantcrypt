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

from .. import constants as const
from .. import utils
from .base_kem import BaseKEM


__all__ = ["MLKEM_512", "MLKEM_768", "MLKEM_1024"]


class MLKEM_512(BaseKEM):
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the MLKEM_512 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for
			the current platform *(any-select mode)*. This is a fatal error
			which requires the library to be reinstalled, because all platforms
			should have CLEAN binaries available.
		"""
		super().__init__(variant)

	@property
	def name(self) -> str:
		return const.SupportedAlgos.MLKEM_512.name


class MLKEM_768(BaseKEM):
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the MLKEM_768 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for
			the current platform *(any-select mode)*. This is a fatal error
			which requires the library to be reinstalled, because all platforms
			should have CLEAN binaries available.
		"""
		super().__init__(variant)

	@property
	def name(self) -> str:
		return const.SupportedAlgos.MLKEM_768.name


class MLKEM_1024(BaseKEM):
	@utils.input_validator()
	def __init__(self, variant: const.PQAVariant = None) -> None:
		"""
		Initializes the MLKEM_1024 instance with C extension binaries.
		User is able to override which underlying binary is used for the
		instance by providing a Variant enum for the variant parameter.

		:param variant: Which binary to use underneath.
			When variant is None *(auto-select mode)*, quantcrypt will
			first try to import AVX2 binaries. If there are no AVX2 binaries
			for the host platform, it will fall back to using CLEAN binaries.
		:raises - ImportError: When an unknown import error has occurred.
		:raises - ModuleNotFoundError: When variant is Variant.AVX2 *(manual-select mode)*
			and quantcrypt cannot find AVX2 binaries for the current platform.
		:raises - SystemExit: When quantcrypt cannot find CLEAN binaries for
			the current platform *(any-select mode)*. This is a fatal error
			which requires the library to be reinstalled, because all platforms
			should have CLEAN binaries available.
		"""
		super().__init__(variant)

	@property
	def name(self) -> str:
		return const.SupportedAlgos.MLKEM_1024.name
