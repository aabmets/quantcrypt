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
from typer import Typer, Option
from typing import Annotated
from quantcrypt.internal.pqa.dss import BaseDSS
from quantcrypt.errors import QuantCryptError
from .. import console, common as com
from . import helpers as hlp


sign_app = Typer(
	name="sign", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored DSS secret key to generate a signature for a file."
)
verify_app = Typer(
	name="verify", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored DSS public key to verify the signature of a file."
)


SignDataFileAtd = Annotated[str, Option(
	'--in-file', '-i', show_default=False, help=""
	"Path to the data file, which will be signed by a DSS algorithm. "
	"The appropriate DSS algorithm is deduced from the contents of the armored key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
VerifyDataFileAtd = Annotated[str, Option(
	'--in-file', '-i', show_default=False, help=""
	"Path to the data file, which will be verified by a DSS algorithm. "
	"The appropriate DSS algorithm is deduced from the contents of the armored key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
WriteSigFileAtd = Annotated[str, Option(
	'--sig-file', '-S', show_default=False, help=""
	"Path to a file where the signature data will be written to, optional. "
	"Defaults to the Current Working Directory, using the data file name with the .sig suffix."
)]
ReadSigFileAtd = Annotated[str, Option(
	'--sig-file', '-S', show_default=False, help=""
	"Path to a file where the signature data will be read from, optional. "
	"Defaults to the Current Working Directory, using the data file name with the .sig suffix."
)]


@sign_app.callback()
def command_sign(
		sk_file: com.SecKeyFileAtd,
		in_file: SignDataFileAtd,
		sig_file: WriteSigFileAtd = None,
		dry_run: com.DryRunAtd = False,
		overwrite: com.OverwriteAtd = False,
		non_interactive: com.NonInteractiveAtd = False
	) -> None:
	paths, dss, armored_key = _common_flow(
		sk_file, in_file, sig_file, dry_run, non_interactive,
		False, "SECRET"
	)
	if paths.sig_file.exists():
		console.ask_overwrite_files(
			non_interactive, overwrite,
			exit_on_false=True
		)
	try:
		signed_file = dss.sign_file(armored_key, paths.in_file)
		with paths.sig_file.open('wb') as file:
			file.write(signed_file.signature)
		console.print_success()
	except QuantCryptError:  # pragma: no cover
		console.raise_error(
			"Unable to sign the data file. "
			"Is the secret key valid?"
		)


@verify_app.callback()
def command_verify(
		pk_file: com.PubKeyFileAtd,
		in_file: VerifyDataFileAtd,
		sig_file: ReadSigFileAtd = None,
		dry_run: com.DryRunAtd = False,
		non_interactive: com.NonInteractiveAtd = False
	) -> None:
	paths, dss, armored_key = _common_flow(
		pk_file, in_file, sig_file, dry_run, non_interactive,
		True, "PUBLIC"
	)
	try:
		with paths.sig_file.open('rb') as file:
			signature = file.read()
		dss.verify_file(armored_key, paths.in_file, signature)
		console.print_success()
	except QuantCryptError:  # pragma: no cover
		console.raise_error(
			"Unable to verify the signature with the "
			"data file! Is the public key valid?"
		)


def _common_flow(
		key_file: str, in_file: str, sig_file: str, dry_run: bool,
		non_interactive: bool, sig_file_must_exist: bool, exp_kt: hlp.ExpKeyType
	) -> tuple[hlp.CommandPaths, BaseDSS, str]:

	paths = hlp.process_paths(key_file, in_file, sig_file, ".sig", sig_file_must_exist)
	console.notify_dry_run(dry_run)

	with paths.key_file.open('r') as file:
		armored_key = file.read()

	dss_class = hlp.determine_dss_class(armored_key, exp_kt)
	dss = dss_class()

	files = [paths.in_file, paths.key_file]
	a, b = [f"[italic sky_blue2]{f.name}[/]" for f in files]

	if exp_kt == "SECRET":
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

	return paths, dss, armored_key
