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
from rich.prompt import Confirm
from rich.console import Console
from quantcrypt.internal import utils


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
	a, b = remove_paths.keys()

	console = Console(soft_wrap=True)
	console.print(
		f"[deep_pink1]QuantCrypt[/] is about to remove [light_slate_blue]'{a}'[/] and "
		f"[light_slate_blue]'{b}'[/] PQC binaries from itself.\nYou will need to reinstall "
		"QuantCrypt if you want to restore these binaries.\n"
	)
	answer = Confirm.ask("Do you want to continue?")
	if answer is False:
		console.print("[gold3]Operation cancelled.[/]\n")
		return

	for path in remove_paths.values():
		shutil.rmtree(path, ignore_errors=True)
	console.print(f"[chartreuse3]Operation successful!\n")
