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
import yaml
import textwrap
import platform
from cffi import FFI
from enum import Enum
from typing import Iterator
from dotmap import DotMap
from pathlib import Path
from functools import lru_cache


class UnsupportedPlatformError(Exception):
	def __init__(self, os: str):
		super().__init__(f"Operating system '{os}' not supported!")


class Variant(Enum):
	CLEAN = "clean"
	AVX2 = "avx2"


class BaseAlgorithm:
	@staticmethod
	@lru_cache
	def read_metadata_file(meta_file: Path) -> DotMap:
		with meta_file.open('r') as file:
			obj: dict = yaml.full_load(file)
		return DotMap(obj)

	@classmethod
	def assert_platform_support(cls, algo_path: Path, variant: Variant):
		meta_file = algo_path.with_name("META.yml")
		metadata = cls.read_metadata_file(meta_file)
		for impl in metadata.implementations:
			if impl.name != variant.value:
				continue
			sup_pfs = impl.get("supported_platforms", [])
			for spf in sup_pfs:
				if spf.architecture != 'x86_64':
					continue
				opsys = platform.system()
				if opsys not in spf.operating_systems:
					raise UnsupportedPlatformError(opsys)

	def __init__(self, name: str, variant: Variant, subdir: str, ffi_cdefs: str):
		pqclean = find_pqclean_dir()
		variant_path = pqclean / f"{subdir}/{name}/{variant.value}"
		self.assert_platform_support(variant_path, variant)

		self.variant: str = variant.value
		self.name: str = name.replace('-', '_')
		self.header_file: str = (variant_path / "api.h").as_posix()
		self.variant_files: list[str] = [
			file.as_posix() for file in variant_path.rglob("**/*")
			if file.is_file() and file.name.endswith(".c")
		]
		self.ffi_cdefs: str = textwrap.dedent(
			ffi_cdefs.format(namespace='_'.join([
				"PQCLEAN",
				name.replace('-', '').upper(),
				variant.name
			]))
		)


class KemAlgorithm(BaseAlgorithm):
	def __init__(self, name: str, variant: Variant):
		super().__init__(name, variant, subdir="crypto_kem", ffi_cdefs="""
			#define {namespace}_CRYPTO_SECRETKEYBYTES ...
			#define {namespace}_CRYPTO_PUBLICKEYBYTES ...
			#define {namespace}_CRYPTO_CIPHERTEXTBYTES ...
			#define {namespace}_CRYPTO_BYTES ...
			
			int {namespace}_crypto_kem_keypair(
				uint8_t *pk, uint8_t *sk
			);
			int {namespace}_crypto_kem_enc(
				uint8_t *ct, uint8_t *ss, const uint8_t *pk
			);
			int {namespace}_crypto_kem_dec(
				uint8_t *ss, const uint8_t *ct, const uint8_t *sk
			);
		""")


class DssAlgorithm(BaseAlgorithm):
	def __init__(self, name: str, variant: Variant):
		super().__init__(name, variant, subdir="crypto_sign", ffi_cdefs="""
			#define {namespace}_CRYPTO_SECRETKEYBYTES ...
			#define {namespace}_CRYPTO_PUBLICKEYBYTES ...
			#define {namespace}_CRYPTO_BYTES ...
			
			int {namespace}_crypto_sign_keypair(
				uint8_t *pk, uint8_t *sk
			);
			int {namespace}_crypto_sign_signature(
				uint8_t *sig, size_t *siglen, 
				const uint8_t *m, size_t mlen, const uint8_t *sk
			);
			int {namespace}_crypto_sign_verify(
				const uint8_t *sig, size_t siglen, 
				const uint8_t *m, size_t mlen, const uint8_t *pk
			);
			int {namespace}_crypto_sign(
				uint8_t *sm, size_t *smlen, 
				const uint8_t *m, size_t mlen, const uint8_t *sk
			);
			int {namespace}_crypto_sign_open(
				uint8_t *m, size_t *mlen, 
				const uint8_t *sm, size_t smlen, const uint8_t *pk
			);
		""")


def get_supported_algorithms(variant: Variant) -> Iterator[KemAlgorithm | DssAlgorithm]:
	for cls, name in [
		(KemAlgorithm, "kyber1024"),
		(DssAlgorithm, "dilithium5"),
		(DssAlgorithm, "falcon-1024"),
		(DssAlgorithm, "sphincs-shake-256f-simple"),
		(DssAlgorithm, "sphincs-shake-256s-simple")
	]:
		try:
			yield cls(name, variant)
		except UnsupportedPlatformError:
			continue


@lru_cache(maxsize=1)
def find_pqclean_dir() -> Path:
	current_path = Path(__file__).parent.resolve()
	while current_path != current_path.parent:
		path = current_path / 'pqclean'
		if path.is_dir():
			return path
		current_path = current_path.parent
	raise RuntimeError("Must find pqclean dir!")  # pragma: no cover


def get_common_files() -> tuple[str, list[str]]:
	path = find_pqclean_dir() / 'common'
	return path.as_posix(), [
		file.as_posix() for file in path.rglob("**/*")
		if file.is_file() and file.name.endswith(".c")
	]


def main():
	opsys = platform.system()
	com_dir, com_files = get_common_files()

	compiler_args = list()
	linker_args = list()
	libraries = list()

	match opsys:
		case "Linux" | "Darwin":
			compiler_args += ["-O3", "-std=c99"]
		case "Windows":
			compiler_args += ["/O2", "/nologo"]
			linker_args.append("/NODEFAULTLIB:MSVCRTD")
			libraries.append("advapi32")
		case _:
			raise UnsupportedPlatformError(opsys)

	for variant in [Variant.CLEAN, Variant.AVX2]:
		for algo in get_supported_algorithms(variant):
			ffi = FFI()
			ffi.cdef(algo.ffi_cdefs)
			ffi.set_source(
				module_name=f"{opsys}.{variant.value}.{algo.name}",
				source=f'#include "{algo.header_file}"',
				sources=[*com_files, *algo.variant_files],
				include_dirs=[com_dir],
				extra_compile_args=compiler_args,
				extra_link_args=linker_args,
				libraries=libraries,
			)
			ffi.compile(verbose=True)

	source_dir = Path(__file__).with_name(opsys)
	for file in source_dir.rglob("*.c"):
		file.unlink(missing_ok=True)


if __name__ == '__main__':
	main()
