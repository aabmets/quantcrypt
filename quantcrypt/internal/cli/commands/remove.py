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

from typer import Typer
from itertools import product
from quantcrypt.internal import utils, constants as const
from quantcrypt.internal.cli import console, annotations as ats


remove_app = Typer(
    name="remove", invoke_without_command=True, no_args_is_help=True, help=' '.join([
        "Removes compiled PQA binaries from the library by name.",
        "Useful for reducing the size of software bundles when all PQC algorithms are not required.",
        "Usually called in a CI pipeline during the build process."
    ])
)


@remove_app.callback()
def command_remove(
        algorithms: ats.RemoveAlgos,
        keep_algos: ats.KeepAlgos = False,
        dry_run: ats.DryRun = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    console.notify_dry_run(dry_run)
    console.styled_print("QuantCrypt is about to remove compiled PQA binaries from itself.")

    if not non_interactive:
        console.ask_continue(exit_on_false=True)

    algos = const.SupportedAlgos.filter(algorithms, invert=keep_algos)
    variants = const.PQAVariant.members()

    if dry_run:
        console.styled_print("QuantCrypt would have removed the following algorithms:")
        console.pretty_print(', '.join(s.armor_name() for s in algos))
        return

    print()
    bin_path = utils.search_upwards("bin")
    bin_contents = list(bin_path.iterdir())

    for spec, variant in product(algos, variants):  # type: const.AlgoSpec, const.PQAVariant
        module_name = spec.module_name(variant)
        did_remove = False

        for item in bin_contents:
            if spec.module_name(variant) in item.name and item.exists():
                item.unlink()
                did_remove = True
                console.styled_print(f"Successfully removed binaries - {module_name}")

        if not did_remove:
            console.styled_print(f"Binaries already removed - {module_name}")

    print()
    console.print_success()
