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
from quantcrypt.internal.pqa.base_dss import BaseDSS
from quantcrypt.internal import errors, constants as const
from quantcrypt.internal.cli import tools, console, annotations as ats


sign_app = Typer(
    name="sign", invoke_without_command=True, no_args_is_help=True,
    help="Uses an ASCII armored DSS secret key to generate a signature for a file."
)
verify_app = Typer(
    name="verify", invoke_without_command=True, no_args_is_help=True,
    help="Uses an ASCII armored DSS public key to verify the signature of a file."
)


@sign_app.callback()
def command_sign(
        sk_file: ats.SecKeyFile,
        in_file: ats.SignDataFile,
        sig_file: ats.WriteSigFile = None,
        dry_run: ats.DryRun = False,
        overwrite: ats.Overwrite = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    paths, dss, armored_key = _common_flow(
        sk_file, in_file, sig_file, dry_run, non_interactive,
        False, const.PQAKeyType.SECRET
    )
    if paths.sig_file.exists():
        console.ask_overwrite_files(non_interactive, overwrite, True)
    try:
        signed_file = dss.sign_file(armored_key, paths.in_file)
        with paths.sig_file.open('wb') as file:
            file.write(signed_file.signature)
        console.print_success()
    except errors.QuantCryptError:  # pragma: no cover
        msg = "Unable to sign the data file. Is the secret key valid?"
        console.raise_error(msg)


@verify_app.callback()
def command_verify(
        pk_file: ats.PubKeyFile,
        in_file: ats.VerifyDataFile,
        sig_file: ats.ReadSigFile = None,
        dry_run: ats.DryRun = False,
        non_interactive: ats.NonInteractive = False
) -> None:
    paths, dss, armored_key = _common_flow(
        pk_file, in_file, sig_file, dry_run, non_interactive,
        True, const.PQAKeyType.PUBLIC
    )
    try:
        with paths.sig_file.open('rb') as file:
            signature = file.read()
        dss.verify_file(armored_key, paths.in_file, signature)
        console.print_success()
    except errors.QuantCryptError:  # pragma: no cover
        msg = "Unable to verify data file signature! Is the public key valid?"
        console.raise_error(msg)


def _common_flow(
        key_file: str,
        in_file: str,
        sig_file: str,
        dry_run: bool,
        non_interactive: bool,
        sig_file_must_exist: bool,
        key_type: const.PQAKeyType
) -> tuple[tools.CommandPaths, BaseDSS, str]:
    paths = tools.process_paths(
        key_file,
        in_file,
        sig_file,
        const.SignatureFileSuffix,
        sig_file_must_exist
    )
    console.notify_dry_run(dry_run)

    with paths.key_file.open('r') as file:
        armored_key = file.read()

    armor_name = tools.validate_armored_key(armored_key, key_type, const.PQAType.DSS)

    files = [paths.in_file, paths.key_file]
    a, b = [f"[italic sky_blue2]{f.name}[/]" for f in files]

    if key_type == const.PQAKeyType.SECRET:
        console.styled_print(
            f"QuantCrypt is about to sign the {a} data file with the \n"
            f"{b} DSS SK file to create the following signature file: \n"
            f"[italic tan]{paths.sig_file} \n"
        )
    else:
        console.styled_print(
            f"QuantCrypt is about to verify the {a} data file with the \n"
            f"{b} DSS PK file and the following signature file: \n"
            f"[italic tan]{paths.sig_file} \n"
        )
    if not non_interactive:
        console.ask_continue(exit_on_false=True)

    dss_cls = tools.get_pqa_class(armor_name)
    return paths, dss_cls(), armored_key
