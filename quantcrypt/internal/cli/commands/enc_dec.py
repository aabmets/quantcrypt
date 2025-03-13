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
from quantcrypt.cipher import KryptonKEM
from quantcrypt.internal import constants as const
from quantcrypt.internal.cli import tools, console, annotations as ats


enc_app = Typer(
    name="encrypt", invoke_without_command=True, no_args_is_help=True,
    help="Uses an ASCII armored KEM public key to encrypt a file with the Krypton cipher."
)
dec_app = Typer(
    name="decrypt", invoke_without_command=True, no_args_is_help=True,
    help="Uses an ASCII armored KEM secret key to decrypt a file with the Krypton cipher."
)


@enc_app.callback()
def command_encrypt(
        pk_file: ats.PubKeyFile,
        in_file: ats.EncInFile,
        out_file: ats.EncOutFile = None,
        dry_run: ats.DryRun = False,
        overwrite: ats.Overwrite = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    paths = tools.process_paths(pk_file, in_file, out_file, const.KryptonFileSuffix)
    _common_flow(paths, dry_run, overwrite, non_interactive, const.PQAKeyType.PUBLIC)


@dec_app.callback()
def command_decrypt(
        sk_file: ats.SecKeyFile,
        in_file: ats.DecInFile,
        out_file: ats.DecOutFile = None,
        dry_run: ats.DryRun = False,
        overwrite: ats.Overwrite = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    paths = tools.process_paths(sk_file, in_file, out_file, const.KryptonFileSuffix)
    _common_flow(paths, dry_run, overwrite, non_interactive, const.PQAKeyType.SECRET)


def _common_flow(
        paths: tools.CommandPaths,
        dry_run: ats.DryRun,
        overwrite: ats.Overwrite,
        non_interactive: ats.NonInteractive,
        key_type: const.PQAKeyType
) -> None:
    console.notify_dry_run(dry_run)

    with paths.key_file.open('r') as file:
        armored_key = file.read()

    armor_name = tools.validate_armored_key(armored_key, key_type, const.PQAType.KEM)

    files = [paths.in_file, paths.key_file]
    a, b = [f"[italic sky_blue2]{f.name.lower()}[/]" for f in files]

    if key_type == const.PQAKeyType.PUBLIC:
        console.styled_print(
            f"QuantCrypt is about to encrypt the {a} plaintext file with the \n"
            f"{b} KEM PK file into the following binary ciphertext file: \n"
            f"[italic tan]{paths.out_file} \n"
        )
    else:
        console.styled_print(
            f"QuantCrypt is about to decrypt the {a} ciphertext file with \n"
            f"the {b} KEM SK file into the following plaintext file: \n"
            f"[italic tan]{paths.out_file} \n"
        )

    if not non_interactive:
        console.ask_continue(exit_on_false=True)

    if paths.out_file.exists():
        console.ask_overwrite_files(
            non_interactive, overwrite,
            exit_on_false=True
        )

    if dry_run:
        console.styled_print("QuantCrypt would have created the following file:")
        console.pretty_print([paths.out_file.as_posix()])
    else:
        kem_cls = tools.get_pqa_class(armor_name)
        krypton = KryptonKEM(kem_cls)
        if key_type == const.PQAKeyType.PUBLIC:
            krypton.encrypt(
                public_key=armored_key,
                data_file=paths.in_file,
                output_file=paths.out_file
            )
        else:
            krypton.decrypt_to_file(
                secret_key=armored_key,
                encrypted_file=paths.in_file,
                output_file=paths.out_file
            )
        console.print_success()
