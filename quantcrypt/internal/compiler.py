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
import os
import shutil
import platform
import itertools
from cffi import FFI
from typing import Generator
from pathlib import Path
from textwrap import dedent
from dataclasses import dataclass
from contextlib import contextmanager
from quantcrypt.internal import constants as const
from quantcrypt.internal import pqclean
from quantcrypt.internal import errors
from quantcrypt.internal import utils


@dataclass(frozen=True)
class Target:
    spec: const.AlgoSpec
    variant: const.PQAVariant
    source_dir: Path | None
    required_flags: list[str] | None
    accepted: bool

    @property
    def _kem_cdefs(self) -> str:
        return dedent("""
            #define {cdef_name}_CRYPTO_SECRETKEYBYTES ...
            #define {cdef_name}_CRYPTO_PUBLICKEYBYTES ...
            #define {cdef_name}_CRYPTO_CIPHERTEXTBYTES ...
            #define {cdef_name}_CRYPTO_BYTES ...

            int {cdef_name}_crypto_kem_keypair(
                uint8_t *pk, uint8_t *sk
            );
            int {cdef_name}_crypto_kem_enc(
                uint8_t *ct, uint8_t *ss, const uint8_t *pk
            );
            int {cdef_name}_crypto_kem_dec(
                uint8_t *ss, const uint8_t *ct, const uint8_t *sk
            );
        """.format(cdef_name=self.cdef_name))

    @property
    def _dss_cdefs(self) -> str:
        return dedent("""
            #define {cdef_name}_CRYPTO_SECRETKEYBYTES ...
			#define {cdef_name}_CRYPTO_PUBLICKEYBYTES ...
			#define {cdef_name}_CRYPTO_BYTES ...

			int {cdef_name}_crypto_sign_keypair(
				uint8_t *pk, uint8_t *sk
			);
			int {cdef_name}_crypto_sign_signature(
				uint8_t *sig, size_t *siglen, 
				const uint8_t *m, size_t mlen, const uint8_t *sk
			);
			int {cdef_name}_crypto_sign_verify(
				const uint8_t *sig, size_t siglen, 
				const uint8_t *m, size_t mlen, const uint8_t *pk
			);
			int {cdef_name}_crypto_sign(
				uint8_t *sm, size_t *smlen, 
				const uint8_t *m, size_t mlen, const uint8_t *sk
			);
			int {cdef_name}_crypto_sign_open(
				uint8_t *m, size_t *mlen, 
				const uint8_t *sm, size_t smlen, const uint8_t *pk
			);
        """.format(cdef_name=self.cdef_name))

    @property
    def cdef_name(self) -> str:
        return self.spec.cdef_name(self.variant)

    @property
    def module_name(self) -> str:
        return self.spec.module_name(self.variant)

    @property
    def ffi_cdefs(self) -> str:
        if self.spec.type == const.PQAType.KEM:
            return self._kem_cdefs
        return self._dss_cdefs

    @property
    def variant_files(self) -> list[str]:
        return [
            file.as_posix() for file in self.source_dir.rglob("**/*")
            if file.is_file() and file.name.endswith(".c")
        ]

    @property
    def include_directive(self) -> str:
        header_file = self.source_dir / "api.h"
        return f'#include "{header_file.as_posix()}"'

    @property
    def compiler_args(self) -> list[str]:
        opsys = platform.system().lower()
        arch = platform.machine().lower()
        extra_flags: list[str] = []
        if opsys == "windows" and arch in const.AMDArches:
            for flag in self.required_flags:
                extra_flags.append(f"/arch:{flag.upper()}")
            return ["/O2", "/MD", "/nologo", *extra_flags]
        elif opsys in ["linux", "darwin"]:
            if arch in const.AMDArches:
                for flag in self.required_flags:
                    extra_flags.append(f"-m{flag.lower()}")
            elif arch in const.ARMArches:
                extra_flag = "-march=armv8.5-a"
                for flag in self.required_flags:
                    extra_flag += f"+{flag.lower()}"
                extra_flags.append(extra_flag)
            return [
                "-s", "-fdata-sections", "-ffunction-sections",
                "-O3", "-flto", "-std=c99", *extra_flags,
            ]
        raise errors.UnsupportedPlatformError

    @property
    def linker_args(self) -> list[str]:
        if platform.system().lower() == "windows":
            return ["/NODEFAULTLIB:MSVCRTD"]
        return []

    @property
    def libraries(self) -> list[str]:
        if platform.system().lower() == "windows":
            return ["advapi32"]
        return []


class Compiler:
    @staticmethod
    def get_compile_targets() -> tuple[list[Target], list[Target]]:
        accepted: list[Target] = []
        rejected: list[Target] = []
        algos = const.SupportedAlgos.values()
        variants = const.PQAVariant.members()
        for spec, variant in itertools.product(algos, variants):
            source_dir, required_flags = pqclean.check_platform_support(spec, variant)
            acceptable = source_dir and variant in const.SupportedVariants
            (accepted if acceptable else rejected).append(Target(
                spec=spec,
                variant=variant,
                source_dir=source_dir,
                required_flags=required_flags,
                accepted=acceptable
            ))
        return accepted, rejected

    @classmethod
    @contextmanager
    def build_path(cls) -> Generator[None, None, None]:
        old_cwd = os.getcwd()
        bin_path = utils.search_upwards("bin")
        for path in bin_path.iterdir():
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                path.unlink()
        new_cwd = bin_path / "build"
        new_cwd.mkdir(parents=True, exist_ok=True)
        os.chdir(new_cwd)
        yield
        for path in new_cwd.iterdir():  # type: Path
            if path.is_file() and path.suffix in [".pyd", ".so"]:
                shutil.copyfile(path, bin_path / path.name)
        os.chdir(old_cwd)
        shutil.rmtree(new_cwd, ignore_errors=True)

    @staticmethod
    def compile(target: Target) -> None:
        com_dir, com_files = pqclean.get_common_filepaths(target.variant)
        ffi = FFI()
        ffi.cdef(target.ffi_cdefs)
        ffi.set_source(
            module_name=target.module_name,
            source=target.include_directive,
            sources=[*com_files, *target.variant_files],
            include_dirs=[com_dir],
            extra_compile_args=target.compiler_args,
            extra_link_args=target.linker_args,
            libraries=target.libraries,
        )
        ffi.compile(verbose=False)

    @classmethod
    def run(cls) -> None:
        if not pqclean.check_sources_exist():
            pqclean.download_extract_pqclean()
        accepted, rejected = cls.get_compile_targets()
        if not accepted:
            return
        with cls.build_path():
            for target in accepted:
                cls.compile(target)
