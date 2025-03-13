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

import string
from typer import Typer
from quantcrypt.internal.cli import tools, console, annotations as ats


keygen_app = Typer(
    name="keygen", invoke_without_command=True, no_args_is_help=True,
    help="Generates an ASCII armored keypair using a KEM or a DSS algorithm."
)


@keygen_app.callback()
def command_keygen(
        algorithm: ats.PQAlgorithm,
        identifier: ats.Identifier = None,
        directory: ats.Directory = None,
        dry_run: ats.DryRun = False,
        overwrite: ats.Overwrite = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    algorithm = algorithm.lower()
    console.notify_dry_run(dry_run)

    prefix = ''
    if identifier:
        _validate_identifier(identifier)
        prefix = f"{identifier}-"

    pqa_cls = tools.get_pqa_class(algorithm)
    apk_name = f"{prefix}{algorithm}-pubkey.qc"
    ask_name = f"{prefix}{algorithm}-seckey.qc"

    target_dir = tools.resolve_directory(directory)
    apk_file = target_dir / apk_name
    ask_file = target_dir / ask_name

    a, b = [f"[italic sky_blue2]{x.name}[/]" for x in [apk_file, ask_file]]
    console.styled_print(
        f"QuantCrypt is about to generate {a} and {b} files\n"
        f"into the following directory: [italic tan]{target_dir}\n"
    )
    if not non_interactive:
        console.ask_continue(exit_on_false=True)

    if apk_file.is_file() or ask_file.is_file():
        console.ask_overwrite_files(
            non_interactive, overwrite,
            exit_on_false=True
        )

    pqa = pqa_cls()
    public_key, secret_key = pqa.keygen()
    apk = pqa.armor(public_key)
    ask = pqa.armor(secret_key)

    if dry_run:
        console.styled_print("QuantCrypt would have created the following files:")
        console.pretty_print([apk_file.as_posix(), ask_file.as_posix()])
    else:
        apk_file.write_text(apk)
        ask_file.write_text(ask)
        console.print_success()


def _validate_identifier(name_arg: str) -> None:
    if len(name_arg) > 15:
        console.raise_error("Unique identifier cannot be longer than 15 characters!")
    allowed_chars = string.ascii_letters + string.digits
    for char in name_arg:
        if char not in allowed_chars:
            console.raise_error(
                "Only characters [[chartreuse3]a-z, A-Z,[/] "
                "0-9] are allowed in the unique identifier!"
            )
