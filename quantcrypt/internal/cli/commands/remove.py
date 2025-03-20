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

import json
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


def remove_spec_variants(
        spec_variants: dict[const.AlgoSpec, list[const.PQAVariant]]
) -> tuple[dict, dict]:
    removed_variants: dict[const.AlgoSpec, list[const.PQAVariant]] = dict()
    already_removed: dict[const.AlgoSpec, list[const.PQAVariant]] = dict()
    bin_path = utils.search_upwards("bin")
    bin_contents = list(bin_path.iterdir())

    for spec, variants in spec_variants.items():  # type: const.AlgoSpec, list[const.PQAVariant]
        for variant in variants:
            did_remove = False

            for item in bin_contents:
                if spec.module_name(variant) in item.name and item.exists():
                    item.unlink()
                    x = removed_variants.get(spec, list())
                    x.append(variant)
                    removed_variants[spec] = x
                    did_remove = True

            if not did_remove:
                y = already_removed.get(spec, list())
                y.append(variant)
                already_removed[spec] = y

    return removed_variants, already_removed


def report_spec_variants(
        spec_variants: dict[const.AlgoSpec, list[const.PQAVariant]]
) -> None:
    armor_names = [s.armor_name() for s in spec_variants.keys()]
    longest_name_len = max(len(n) for n in armor_names) if armor_names else 0

    for spec, variants in spec_variants.items():
        variants_fmt = json.dumps([v.value for v in variants])
        arna_fmt = spec.armor_name().rjust(longest_name_len)
        console.styled_print(f"{arna_fmt}: {variants_fmt}")


@remove_app.callback()
def command_remove(
        algorithms: ats.RemoveAlgos,
        keep_algos: ats.KeepAlgos = False,
        only_ref: ats.OnlyRef = False,
        dry_run: ats.DryRun = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    if only_ref and not keep_algos:
        console.raise_error("Cannot use --only-ref without --keep")

    chosen_algos = const.SupportedAlgos.filter(algorithms)
    if len(chosen_algos) != len(algorithms):
        algo_names = [s.armor_name() for s in chosen_algos]
        bad_names = [a for a in algorithms if a.upper() not in algo_names]
        if bad_names:  # pragma: no branch
            console.raise_error(
                f"Unknown algorithm name(s): {json.dumps(bad_names)}. " +
                "Please choose algorithm names from the following list:\n" +
                ' | '.join(const.SupportedAlgos.armor_names())
            )

    console.notify_dry_run(dry_run)
    console.styled_print("QuantCrypt is about to remove compiled PQA binaries from itself.")

    if not non_interactive:
        console.ask_continue(exit_on_false=True)

    variants = const.PQAVariant.members()
    if only_ref:
        algorithms = [a.upper() for a in algorithms]
        algos = const.SupportedAlgos
    else:
        algos = const.SupportedAlgos.filter(algorithms, invert=keep_algos)

    to_remove: dict[const.AlgoSpec, list[const.PQAVariant]] = dict()
    for spec, variant in product(algos, variants):  # type: const.AlgoSpec, const.PQAVariant
        if only_ref and spec.armor_name() in algorithms and variant == const.PQAVariant.REF:
            continue
        variants = to_remove.get(spec, list())
        variants.append(variant)
        to_remove[spec] = variants

    if dry_run:
        console.styled_print("\nQuantCrypt would have removed the following algorithms and their variants:")
        report_spec_variants(to_remove)
        return

    removed_variants, already_removed = remove_spec_variants(to_remove)

    console.styled_print("\nSuccessfully removed binaries: ")
    report_spec_variants(removed_variants)

    console.styled_print("\nAlready removed binaries: ")
    report_spec_variants(already_removed)

    print()
    console.print_success()
