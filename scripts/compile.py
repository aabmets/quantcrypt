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
import os
import yaml
import shutil
import textwrap
import platform
from cffi import FFI
from enum import Enum
from typing import Iterator
from dotmap import DotMap
from pathlib import Path
from functools import lru_cache


class UnsupportedPlatformError(Exception):
	def __init__(self):
		super().__init__(f"Operating system '{platform.system()}' not supported!")


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
	def assert_platform_support(cls, variant_path: Path, variant: Variant):
		if variant == Variant.CLEAN:
			return
		meta_file = variant_path.with_name("META.yml")
		metadata = cls.read_metadata_file(meta_file)
		impl = [
			impl for impl in metadata.implementations
			if impl.name == Variant.AVX2.value
		][0]
		spf = [
			spf for spf in impl.supported_platforms
			if spf.architecture == "x86_64"
		][0]
		if ops := spf.get("operating_systems", []):
			if platform.system() not in ops:
				raise UnsupportedPlatformError

	def __init__(self, name: str, variant: Variant, subdir: str, ffi_cdefs: str):
		pqclean = find_abs_path(rel_path='pqclean')
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


@lru_cache
def find_abs_path(rel_path: str, from_file: str = __file__) -> Path:
	current_path = Path(from_file).parent.resolve()
	while current_path != current_path.parent:
		search_path = current_path / rel_path
		if search_path.exists():
			return search_path
		elif (current_path / ".git").exists():
			break
		current_path = current_path.parent
	raise RuntimeError(f"Cannot find '{rel_path}' in repo!")


def get_common_files(variant: Variant) -> tuple[str, list[str]]:
	path = find_abs_path(rel_path="pqclean/common")
	common, keccak = list(), list()

	for file in path.rglob("**/*"):
		if file.is_file() and file.suffix == '.c':
			files = keccak if 'keccak4x' in file.as_posix() else common
			files.append(file.as_posix())

	common.extend(keccak if variant == Variant.AVX2 else [])
	return path.as_posix(), common


def main():
	os.chdir(Path(__file__).parent)
	opsys = platform.system()

	for variant in [Variant.CLEAN]:  # AVX2 currently not supported
		com_dir, com_files = get_common_files(variant)
		compiler_args = list()
		linker_args = list()
		libraries = list()

		match opsys:
			case "Linux" | "Darwin":
				compiler_args.extend([
					"-s", "-flto", "-std=c99",
					"-Os", "-ffunction-sections",
					"-O3", "-fdata-sections",
				])
				if variant == Variant.AVX2:
					compiler_args.extend([
						"-mavx2", "-maes",
						"-mbmi2", "-mpopcnt"
					])
			case "Windows":
				compiler_args.extend(["/O2", "/MD", "/nologo"])
				if variant == Variant.AVX2:
					compiler_args.append("/arch:AVX2")
				linker_args.append("/NODEFAULTLIB:MSVCRTD")
				libraries.append("advapi32")
			case _:
				raise UnsupportedPlatformError

		for algo in get_supported_algorithms(variant):
			ffi = FFI()
			ffi.cdef(algo.ffi_cdefs)
			ffi.set_source(
				module_name=f"bin.{opsys}.{variant.value}.{algo.name}",
				source=f'#include "{algo.header_file}"',
				sources=[*com_files, *algo.variant_files],
				include_dirs=[com_dir],
				extra_compile_args=compiler_args,
				extra_link_args=linker_args,
				libraries=libraries,
			)
			ffi.compile(verbose=True)

	src_dir = Path(__file__).with_name("bin")
	for path in src_dir.rglob("*.*"):
		if path.is_file() and path.suffix not in [".pyd", ".so"]:
			path.unlink(missing_ok=True)

	dst_dir = find_abs_path("quantcrypt/internal")
	shutil.rmtree(dst_dir / "bin", ignore_errors=True)
	shutil.move(src_dir, dst_dir)


if __name__ == '__main__':
	main()
