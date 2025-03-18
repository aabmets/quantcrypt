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
import re
import os
import ast
import sys
import shutil
import platform
import setuptools
import subprocess
from cffi import FFI
from typing import Generator
from pathlib import Path
from textwrap import dedent
from itertools import product
from dataclasses import dataclass
from contextlib import contextmanager
from quantcrypt.internal import constants as const
from quantcrypt.internal import pqclean, errors, utils


@dataclass(frozen=True)
class Target:
    spec: const.AlgoSpec
    variant: const.PQAVariant
    source_dir: Path
    required_flags: list[str]
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
            if file.is_file() and file.suffix in ['.c', '.S', '.s']
        ]

    @property
    def include_directive(self) -> str:
        header_file = self.source_dir / "api.h"
        return f'#include "{header_file.as_posix()}"'

    def _add_linux_compiler_args(self, extra_flags: list[str]) -> None:
        arch = platform.machine().lower()
        extra_flags.append("-s")
        if arch in const.AMDArches:
            for flag in self.required_flags:
                extra_flags.append(f"-m{flag.lower()}")
        elif arch in const.ARMArches:
            march_flag = "-march=armv8.5-a"
            for flag in self.required_flags:
                march_flag += f"+{flag.lower()}"
            extra_flags.append(march_flag)

    @property
    def compiler_args(self) -> list[str]:  # pragma: no cover
        opsys = platform.system().lower()
        arch = platform.machine().lower()

        if opsys not in ("windows", "linux", "darwin"):
            raise errors.UnsupportedPlatformError

        extra_flags: list[str] = []
        unix_flags = [
            "-fdata-sections", "-ffunction-sections",
            "-O3", "-flto", "-std=c99"
        ]
        if opsys == "windows" and arch in const.AMDArches:
            for flag in self.required_flags:
                extra_flags.append(f"/arch:{flag.upper()}")
            return ["/O2", "/MD", "/nologo", *extra_flags]
        elif opsys == "linux":
            self._add_linux_compiler_args(extra_flags)

        unix_flags.extend(extra_flags)
        return unix_flags

    @property
    def linker_args(self) -> list[str]:  # pragma: no cover
        if platform.system().lower() == "windows":
            return ["/NODEFAULTLIB:MSVCRTD"]
        return []

    @property
    def libraries(self) -> list[str]:  # pragma: no cover
        if platform.system().lower() == "windows":
            return ["advapi32"]
        return []


class Compiler:
    @staticmethod
    def patch_distutils():  # pragma: no cover
        setuptools_path = Path(setuptools.__file__).parent
        distutils_path = "_distutils/compilers/C/unix.py"
        compiler_path = setuptools_path / distutils_path

        with compiler_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        pattern = re.compile(r'^( {0,4}src_extensions\s*=\s*)(\[[^]]*])')
        did_append = False

        for i, line in enumerate(lines):
            match = pattern.search(line)
            if match:
                prefix, list_str = match.group(1), match.group(2)
                ext_list: list[str] = ast.literal_eval(list_str)  # NOSONAR
                for suffix in ['.S', '.s']:
                    if suffix not in ext_list:
                        ext_list.append(suffix)
                        did_append = True
                lines[i] = prefix + repr(ext_list) + "\n"
                break

        if did_append:
            with compiler_path.open("w", encoding="utf-8") as f:
                f.writelines(lines)

    @staticmethod
    def get_compile_targets(
            target_variants: list[const.PQAVariant],
            target_algos: list[const.AlgoSpec]
    ) -> tuple[list[Target], list[Target]]:
        accepted: list[Target] = []
        rejected: list[Target] = []
        specs = const.SupportedAlgos
        variants = const.PQAVariant.members()
        for spec, variant in product(specs, variants):
            source_dir, required_flags = pqclean.check_platform_support(spec, variant)
            acceptable = (
                source_dir is not None
                and required_flags is not None
                and variant in target_variants
                and spec in target_algos
            )
            (accepted if acceptable else rejected).append(Target(
                spec=spec,
                variant=variant,
                source_dir=source_dir or Path(),
                required_flags=required_flags or [],
                accepted=acceptable
            ))
        return accepted, rejected

    @classmethod
    @contextmanager
    def build_path(cls) -> Generator[None, None, None]:
        old_cwd = os.getcwd()
        bin_path = utils.search_upwards("bin")
        for path in bin_path.iterdir():
            if path.is_file():
                path.unlink()
            else:
                shutil.rmtree(path, ignore_errors=True)
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
    def compile(target: Target, debug: bool) -> None:
        com_dir, com_files = pqclean.get_common_filepaths(target.variant)
        ffi = FFI()
        ffi.cdef(target.ffi_cdefs)
        ffi.set_source(
            module_name=target.module_name,
            source=target.include_directive,
            sources=[*com_files, *target.variant_files],
            include_dirs=[com_dir, target.source_dir.as_posix()],
            extra_compile_args=target.compiler_args,
            extra_link_args=target.linker_args,
            libraries=target.libraries,
        )
        ffi.compile(verbose=debug, debug=debug)

    @staticmethod
    def log_progress(target: Target) -> None:  # pragma: no cover
        algo = target.spec.armor_name()
        variant = target.variant.value
        prefix, suffix = '', "..."
        if __name__ == "__main__":
            prefix = const.SubprocTag
            algo = f"[bold sky_blue2]{algo}[/]"
            variant = f"[italic tan]{variant}[/]"
            suffix = f"[grey46]{suffix}[/]"
        msg = f"{prefix}Compiling {variant} variant of {algo}{suffix}"
        print(msg, flush=True)

    @classmethod
    def run(cls,
            target_variants: list[const.PQAVariant] = None,
            target_algos: list[const.AlgoSpec] = None,
            *,
            in_subprocess: bool = False,
            verbose: bool = False,
            debug: bool = False,
    ) -> subprocess.Popen | list[Target]:
        if target_variants is None:  # pragma: no cover
            target_variants = const.PQAVariant.members()
        if target_algos is None:  # pragma: no cover
            target_algos = const.SupportedAlgos
        if in_subprocess:  # pragma: no cover
            return subprocess.Popen(
                args=[
                    sys.executable, __file__,
                    utils.b64pickle(target_variants),
                    utils.b64pickle(target_algos)
                ],
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                text=True
            )
        pqclean_dir = pqclean.find_pqclean_dir(src_must_exist=False)
        if not pqclean.check_sources_exist(pqclean_dir):
            pqclean.download_extract_pqclean(pqclean_dir)

        accepted, rejected = cls.get_compile_targets(
            target_variants, target_algos
        )
        if not accepted:
            return rejected

        cls.patch_distutils()
        with cls.build_path():
            for target in accepted:
                if verbose or debug:  # pragma: no cover
                    cls.log_progress(target)
                cls.compile(target, debug)

        return rejected


if __name__ == "__main__":
    _target_variants = utils.b64pickle(sys.argv[1])
    _target_algos = utils.b64pickle(sys.argv[2])
    Compiler.run(_target_variants, _target_algos, verbose=True)
