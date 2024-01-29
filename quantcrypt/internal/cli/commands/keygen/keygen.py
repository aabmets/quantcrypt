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
from quantcrypt.kem import Kyber
from quantcrypt.dss import (
	Dilithium,
	Falcon,
	FastSphincs,
	SmallSphincs
)
from . import helpers


keygen_app = Typer(
	name="keygen", no_args_is_help=True, help=""
	"Generates an ASCII armored keypair using a KEM or a DSS algorithm."
)


IdentifierAtd = Annotated[str, Option(
	"--id", "-i", show_default=False, help=""
	"Unique identifier to prepend to the names of the keyfiles, optional."
)]
DirectoryAtd = Annotated[str, Option(
	"--dir", "-d", show_default=False, help=""
	"Directory where to save the generated keypair, optional. "
	"If the directory doesn't exist, it will be created with parents. "
	"If not provided, the keys are saved into the Current Working Directory."
)]
OverwriteAtd = Annotated[bool, Option(
	"--overwrite", "-o", show_default=False, help=""
	"Disables interactive confirmation prompt for overwriting files."
)]
NonInteractiveAtd = Annotated[bool, Option(
	"--non-interactive", "-n", show_default=False, help=""
	"Disables interactive prompts. If the program is going to overwrite "
	"files and the --overwrite option is not separately provided, the "
	"program will exit with an exit code of 1."
)]


@keygen_app.command(name="kyber")
def command_kyber(
		_name: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_ovr: OverwriteAtd = False,
		_ni: NonInteractiveAtd = False
	) -> None:
	"""[KEM] Generates Kyber keys and writes them to disk."""
	helpers.interactive_flow(_name, _dir, _ovr, _ni, Kyber)


@keygen_app.command(name="dilithium")
def command_dilithium(
		_name: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_ovr: OverwriteAtd = False,
		_ni: NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates Dilithium keys and writes them to disk."""
	helpers.interactive_flow(_name, _dir, _ovr, _ni, Dilithium)


@keygen_app.command(name="falcon")
def command_falcon(
		_name: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_ovr: OverwriteAtd = False,
		_ni: NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates Falcon keys and writes them to disk."""
	helpers.interactive_flow(_name, _dir, _ovr, _ni, Falcon)


@keygen_app.command(name="smallsphincs")
def command_smallsphincs(
		_name: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_ovr: OverwriteAtd = False,
		_ni: NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates SmallSphincs keys and writes them to disk."""
	helpers.interactive_flow(_name, _dir, _ovr, _ni, SmallSphincs)


@keygen_app.command(name="fastsphincs")
def command_fastsphincs(
		_name: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_ovr: OverwriteAtd = False,
		_ni: NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates FastSphincs keys and writes them to disk."""
	helpers.interactive_flow(_name, _dir, _ovr, _ni, FastSphincs)
