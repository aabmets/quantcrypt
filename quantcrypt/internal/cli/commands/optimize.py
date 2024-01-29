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
import shutil
import platform
from typer import Typer
from quantcrypt.internal import utils
from quantcrypt.internal.cli.models import StyledConsole


optimize_app = Typer(
	name="optimize", invoke_without_command=True, help=""
	"Removes those PQA binaries which are incompatible with your platform."
)


@optimize_app.callback()
def command_optimize() -> None:
	bin_path = utils.search_upwards(__file__, "bin")
	remove_paths = {
		"Windows": bin_path / "Windows",
		"Linux": bin_path / "Linux",
		"Darwin": bin_path / "Darwin"
	}
	keep = platform.system()
	remove_paths.pop(keep)

	a, b = [f"[sky_blue2]{x}[/]" for x in remove_paths.keys()]
	StyledConsole.print(
		f"QuantCrypt is about to remove {a} and {b} PQC binaries from itself.\n"
		f"You will need to reinstall QuantCrypt if you want to restore these binaries.\n"
	)
	StyledConsole.ask_continue(exit_on_false=True)

	for path in remove_paths.values():
		shutil.rmtree(path, ignore_errors=True)

	StyledConsole.print_success()
