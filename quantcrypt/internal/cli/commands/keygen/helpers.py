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
from quantcrypt.internal.cli.models import StyledConsole
from quantcrypt.internal.pqa.common import BasePQAlgorithm
from quantcrypt.internal import utils


def interactive_flow(
		identifier: str | None,
		directory: str | None,
		overwrite: bool,
		non_interactive: bool,
		algo_cls: Type[BasePQAlgorithm]
) -> None:
	prefix = ''
	if identifier:
		_validate_name(identifier)
		prefix = f"{identifier}-"

	algo_name = algo_cls.__name__.lower()
	apk_name = f"{prefix}{algo_name}-pubkey.qc"
	ask_name = f"{prefix}{algo_name}-seckey.qc"

	target_dir = _resolve_directory(directory)
	apk_file = target_dir / apk_name
	ask_file = target_dir / ask_name

	a, b = [f"[italic sky_blue2]{x.name}[/]" for x in [apk_file, ask_file]]
	StyledConsole.print(
		f"QuantCrypt is about to generate {a} and {b} files\n"
		f"into the following directory: [italic tan]{target_dir}\n"
	)
	if not non_interactive:
		StyledConsole.ask_continue(exit_on_false=True)

	if apk_file.is_file() or ask_file.is_file():
		if non_interactive and not overwrite:
			StyledConsole.raise_error(
				"Must enable file overwriting with the [bold turquoise2]"
				"--overwrite[/] option in non-interactive mode."
			)
		elif not overwrite:
			StyledConsole.ask_overwrite_files(exit_on_false=True)

	pqa = algo_cls()
	public_key, secret_key = pqa.keygen()
	apk = pqa.armor(public_key)
	ask = pqa.armor(secret_key)

	apk_file.write_text(apk)
	ask_file.write_text(ask)

	StyledConsole.print_success()


def _validate_name(name_arg: str) -> None:
	if name_arg is not None:
		if len(name_arg) > 15:
			StyledConsole.raise_error(
				"Unique identifier cannot be longer than 15 characters!"
			)
		allowed_chars = string.ascii_letters + string.digits
		for char in name_arg:
			if char not in allowed_chars:
				StyledConsole.raise_error(
					"Only characters [[chartreuse3]a-z, A-Z,[/] "
					"0-9] are allowed in the unique identifier!"
				)


def _resolve_directory(dir_arg: str | None) -> Path:
	target_dir = utils.resolve_relpath(dir_arg)
	if target_dir.is_file():
		StyledConsole.raise_error(
			f"The provided path is not a directory: "
			f"[italic tan]{target_dir}"
		)
	elif not target_dir.exists():
		target_dir.mkdir(parents=True)
	return target_dir
