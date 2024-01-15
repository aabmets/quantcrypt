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
from typing import Type
from pathlib import Path
from typing import Annotated
from typer import Typer, Option
from quantcrypt.internal.pqa.common import BasePQAlgorithm
from quantcrypt.kem import Kyber
from quantcrypt.dss import (
	Dilithium,
	Falcon,
	FastSphincs,
	SmallSphincs
)

keygen_app = Typer(
	name="keygen", no_args_is_help=True, help=
	"Select a Post-Quantum Algorithm to generate keys for. "
	"All sub-commands have identical call options. You can see the "
	"available options by calling a sub-command with the --help option."
)

NameAtd = Annotated[str, Option(
	"--name", "-n", show_default=False, help=
	'Unique identifier for the keyfile names, optional. '
	'If not provided, file names will be without a unique identifier.'
)]
PathAtd = Annotated[str, Option(
	"--dir", "-d", show_default=False, help=
	'Directory where to save the generated keypair, optional. '
	'If not provided, the keys are saved into the current working directory.'
)]


def keygen_interactive_flow(
		name_arg: str | None,
		dir_arg: str | None,
		algo_name: str,
		algo_cls: Type[BasePQAlgorithm]
) -> None:
	if name_arg is not None:
		if len(name_arg) > 15:
			raise SystemExit("ERROR! Cannot use an identifier longer than 15 characters!")
		allowed_chars = string.ascii_letters + string.digits

		for char in name_arg:
			if char not in allowed_chars:
				raise SystemExit("ERROR! Only characters [a-z, A-Z, 0-9] are allowed in the identifier!")

	tgt_dir = Path(dir_arg) if dir_arg else Path.cwd()
	if not tgt_dir.is_dir():
		raise SystemExit("ERROR! The provided path is not a valid directory!")

	pqa = algo_cls()
	public_key, secret_key = pqa.keygen()
	apk = pqa.armor(public_key)
	ask = pqa.armor(secret_key)

	prefix = f"{name_arg}-" if name_arg else ''
	apk_name = f"{prefix}{algo_name}-pubkey.qc"
	ask_name = f"{prefix}{algo_name}-seckey.qc"
	apk_file = tgt_dir / apk_name
	ask_file = tgt_dir / ask_name

	def user_input_gate(file_names: str, plural: bool):
		file_noun = "files" if plural else "a file"
		print(f"The target directory already contains {file_noun} named {file_names}.")
		answer = input("Okay to overwrite? (y/N): ").upper()
		if answer == 'N':
			reason = "existing files" if plural else "an existing file"
			raise SystemExit(f"\nUnable to continue due to {reason}.\n")
		print()

	if apk_file.is_file() and ask_file.is_file():
		user_input_gate(f"'{apk_name}' and '{ask_name}'", True)
	elif apk_file.is_file():
		user_input_gate(f"'{apk_name}'", False)
	elif ask_file.is_file():
		user_input_gate(f"'{ask_name}'", False)

	apk_file.write_text(apk)
	ask_file.write_text(ask)
	print(f"Successfully generated '{apk_name}' and '{ask_name}' keyfiles!\n")


@keygen_app.command(name="kyber")
def command_optimize(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[KEM] Generates Kyber keys and writes them to disk.
	"""
	keygen_interactive_flow(name_arg, dir_arg, "kyber", Kyber)


@keygen_app.command(name="dilithium")
def command_optimize(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates Dilithium keys and writes them to disk.
	"""
	keygen_interactive_flow(name_arg, dir_arg, "dilithium", Dilithium)


@keygen_app.command(name="falcon")
def command_optimize(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates Falcon keys and writes them to disk.
	"""
	keygen_interactive_flow(name_arg, dir_arg, "falcon", Falcon)


@keygen_app.command(name="smallsphincs")
def command_optimize(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates SmallSphincs keys and writes them to disk.
	"""
	keygen_interactive_flow(name_arg, dir_arg, "smallsphincs", SmallSphincs)


@keygen_app.command(name="fastsphincs")
def command_optimize(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates FastSphincs keys and writes them to disk.
	"""
	keygen_interactive_flow(name_arg, dir_arg, "fastsphincs", FastSphincs)
