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
from typing import Annotated
from typer import Typer, Option
from quantcrypt.cipher import KryptonKEM
from .. import console, common as com
from . import helpers as hlp


enc_app = Typer(
	name="encrypt", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored KEM public key to encrypt a file with the Krypton cipher."
)
dec_app = Typer(
	name="decrypt", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored KEM secret key to decrypt a file with the Krypton cipher."
)


EncInFileAtd = Annotated[str, Option(
	'--in-file', '-i', show_default=False, help=""
	"Path to the plaintext data file, which will be encrypted with the Krypton cipher. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
EncOutFileAtd = Annotated[str, Option(
	'--out-file', '-o', show_default=False, help=""
	"Path to the output file where the encrypted data will be written to, optional. "
	"Defaults to the Current Working Directory, using the data file name with the .kptn suffix."
)]
DecInFileAtd = Annotated[str, Option(
	'--in-file', '-i', show_default=False, help=""
	"Path to the ciphertext data file, which will be decrypted with the Krypton cipher. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
DecOutFileAtd = Annotated[str, Option(
	'--out-file', '-o', show_default=False, help=""
	"Path to the output file where the decrypted data will be written to, optional. "
	"Defaults to the Current Working Directory, using the original filename of the "
	"plaintext file that was stored into the ciphertext file."
)]


@enc_app.callback()
def command_encrypt(
		pk_file: com.PubKeyFileAtd,
		in_file: EncInFileAtd,
		out_file: EncOutFileAtd = None,
		dry_run: com.DryRunAtd = False,
		overwrite: com.OverwriteAtd = False,
		non_interactive: com.NonInteractiveAtd = False
	) -> None:
	paths = hlp.process_paths(pk_file, in_file, out_file, '.kptn')
	_interactive_flow(paths, dry_run, overwrite, non_interactive, 'PUBLIC')


@dec_app.callback()
def command_decrypt(
		sk_file: com.SecKeyFileAtd,
		in_file: DecInFileAtd,
		out_file: DecOutFileAtd = None,
		dry_run: com.DryRunAtd = False,
		overwrite: com.OverwriteAtd = False,
		non_interactive: com.NonInteractiveAtd = False
	) -> None:
	paths = hlp.process_paths(sk_file, in_file, out_file, '.kptn')
	_interactive_flow(paths, dry_run, overwrite, non_interactive, 'SECRET')


def _interactive_flow(
		paths: hlp.CommandPaths,
		dry_run: com.DryRunAtd,
		overwrite: com.OverwriteAtd,
		non_interactive: com.NonInteractiveAtd,
		exp_kt: hlp.ExpKeyType
	) -> None:
	console.notify_dry_run(dry_run)

	with paths.key_file.open('r') as file:
		armored_key = file.read()

	kem_class = hlp.determine_kem_class(armored_key, exp_kt)

	files = [paths.in_file, paths.key_file]
	a, b = [f"[italic sky_blue2]{f.name}[/]" for f in files]

	if exp_kt == 'PUBLIC':
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
		krypton = KryptonKEM(kem_class)
		if exp_kt == 'PUBLIC':
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
