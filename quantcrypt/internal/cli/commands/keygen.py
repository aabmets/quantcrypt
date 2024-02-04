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
from typing import Annotated
from typer import Typer, Option
from quantcrypt.kem import Kyber
from quantcrypt.dss import Dilithium, Falcon, FastSphincs, SmallSphincs
from quantcrypt.internal.pqa.common import BasePQAlgorithm
from .. import console, common as com
from . import helpers as hlp


app = Typer(
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


@app.command(name="kyber")
def command_kyber(
		_id: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_dry: com.DryRunAtd = False,
		_ow: com.OverwriteAtd = False,
		_ni: com.NonInteractiveAtd = False
	) -> None:
	"""[KEM] Generates Kyber keys and writes them to disk."""
	_interactive_flow(_id, _dir, _dry, _ow, _ni, Kyber)


@app.command(name="dilithium")
def command_dilithium(
		_id: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_dry: com.DryRunAtd = False,
		_ow: com.OverwriteAtd = False,
		_ni: com.NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates Dilithium keys and writes them to disk."""
	_interactive_flow(_id, _dir, _dry, _ow, _ni, Dilithium)


@app.command(name="falcon")
def command_falcon(
		_id: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_dry: com.DryRunAtd = False,
		_ow: com.OverwriteAtd = False,
		_ni: com.NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates Falcon keys and writes them to disk."""
	_interactive_flow(_id, _dir, _dry, _ow, _ni, Falcon)


@app.command(name="smallsphincs")
def command_smallsphincs(
		_id: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_dry: com.DryRunAtd = False,
		_ow: com.OverwriteAtd = False,
		_ni: com.NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates SmallSphincs keys and writes them to disk."""
	_interactive_flow(_id, _dir, _dry, _ow, _ni, SmallSphincs)


@app.command(name="fastsphincs")
def command_fastsphincs(
		_id: IdentifierAtd = None,
		_dir: DirectoryAtd = None,
		_dry: com.DryRunAtd = False,
		_ow: com.OverwriteAtd = False,
		_ni: com.NonInteractiveAtd = False
	) -> None:
	"""[DSS] Generates FastSphincs keys and writes them to disk."""
	_interactive_flow(_id, _dir, _dry, _ow, _ni, FastSphincs)


def _interactive_flow(
		identifier: str | None,
		directory: str | None,
		dry_run: bool,
		overwrite: bool,
		non_interactive: bool,
		algo_cls: Type[BasePQAlgorithm]
) -> None:
	console.notify_dry_run(dry_run)

	prefix = ''
	if identifier:
		_validate_identifier(identifier)
		prefix = f"{identifier}-"

	algo_name = algo_cls.__name__.lower()
	apk_name = f"{prefix}{algo_name}-pubkey.qc"
	ask_name = f"{prefix}{algo_name}-seckey.qc"

	target_dir = hlp.resolve_directory(directory)
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

	pqa = algo_cls()
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
