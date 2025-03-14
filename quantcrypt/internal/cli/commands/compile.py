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
import sys
import platform
from typer import Typer
from quantcrypt.internal import constants as const
from quantcrypt.internal.compiler import Compiler
from quantcrypt.internal.cli import tools, console, annotations as ats


compile_app = Typer(
    name="compile", invoke_without_command=True, help=' '.join([
        "Compiles PQA binaries from PQClean C source code using CFFI.",
        "Requires an active internet connection and pre-installed platform-specific build tools.",
        "Calling this command without options begins the compilation of only clean reference variants.",
        "Use the --help option to see all available options."
    ])
)


def run_compiler(variants: list[const.PQAVariant]) -> None:
    sys.stdout = open(os.devnull, 'w')
    Compiler().run(variants)


@compile_app.callback()
def command_compile(
        algorithms: ats.CompileAlgos = None,
        with_opt: ats.WithOpt = None,
        dry_run: ats.DryRun = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    console.notify_dry_run(dry_run)

    variants = [const.PQAVariant.REF]
    if with_opt:
        arch = platform.machine().lower()
        if arch in const.AMDArches:
            variants.append(const.PQAVariant.OPT_AMD)
        elif arch in const.ARMArches:
            variants.append(const.PQAVariant.OPT_ARM)
        else:  # pragma: no branch
            console.raise_error("This machine does not support optimized variants.")

    algos = [] if algorithms else const.SupportedAlgos
    for armor_name in algorithms or []:
        if spec := const.SupportedAlgos.filter(armor_name):
            algos.append(spec)

    variants_fmt = 'only the [italic tan]clean[/]'
    if len(variants) > 1:
        variants_fmt = ' and '.join(f"[italic tan]{v.value}[/]" for v in variants)

    console.styled_print(
        f"QuantCrypt is about to compile {variants_fmt} "
        f"variants of [bold sky_blue2]PQC algorithms[/]."
    )
    if not non_interactive:
        console.ask_continue(exit_on_false=True)

    console.styled_print("\nInitializing compilation[grey46]...[/]\n")
    process = Compiler.run(variants, algos, in_subprocess=True)

    for line in process.stdout:  # type: str
        if line.startswith(const.SubprocTag):
            line = line.lstrip(const.SubprocTag)
            console.styled_print(line.rstrip())

    process.wait()
    print()
    if process.returncode == 0:
        console.print_success()
    else:
        console.raise_error("Failed to compile PQC algorithms.")
