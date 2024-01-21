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


NameAtd = Annotated[str, Option(
	"--name", "-n", show_default=False, help=""
	'Unique identifier for the keyfile names, optional. '
	'If not provided, file names will be without a unique identifier.'
)]
PathAtd = Annotated[str, Option(
	"--dir", "-d", show_default=False, help=""
	'Directory where to save the generated keypair, optional. '
	'If not provided, the keys are saved into the current working directory.'
)]


@keygen_app.command(name="kyber")
def command_kyber(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[KEM] Generates Kyber keys and writes them to disk.
	"""
	helpers.keygen_interactive_flow(
		name_arg, dir_arg,
		algo_name="kyber",
		algo_cls=Kyber
	)


@keygen_app.command(name="dilithium")
def command_dilithium(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates Dilithium keys and writes them to disk.
	"""
	helpers.keygen_interactive_flow(
		name_arg, dir_arg,
		algo_name="dilithium",
		algo_cls=Dilithium
	)


@keygen_app.command(name="falcon")
def command_falcon(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates Falcon keys and writes them to disk.
	"""
	helpers.keygen_interactive_flow(
		name_arg, dir_arg,
		algo_name="falcon",
		algo_cls=Falcon
	)


@keygen_app.command(name="smallsphincs")
def command_smallsphincs(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates SmallSphincs keys and writes them to disk.
	"""
	helpers.keygen_interactive_flow(
		name_arg, dir_arg,
		algo_name="smallsphincs",
		algo_cls=SmallSphincs
	)


@keygen_app.command(name="fastsphincs")
def command_fastsphincs(name_arg: NameAtd = None, dir_arg: PathAtd = None) -> None:
	"""
	[DSS] Generates FastSphincs keys and writes them to disk.
	"""
	helpers.keygen_interactive_flow(
		name_arg, dir_arg,
		algo_name="fastsphincs",
		algo_cls=FastSphincs
	)
