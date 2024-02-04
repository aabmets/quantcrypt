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
from .. import common as com
from .. import console


app = Typer(
	name="optimize", invoke_without_command=True, help=""
	"Removes those PQA binaries which are incompatible with the host platform."
)


@app.callback()
def command_optimize(dry_run: com.DryRunAtd = False) -> None:
	console.notify_dry_run(dry_run)

	bin_path = utils.search_upwards(__file__, "bin")
	remove_paths = {
		"Windows": bin_path / "Windows",
		"Linux": bin_path / "Linux",
		"Darwin": bin_path / "Darwin"
	}
	keep = platform.system()
	remove_paths.pop(keep)

	a, b = [f"[sky_blue2]{x}[/]" for x in remove_paths.keys()]
	console.styled_print(
		f"QuantCrypt is about to remove {a} and {b} PQC binaries from itself.\n"
		f"You will need to reinstall QuantCrypt if you want to restore these binaries.\n"
	)
	console.ask_continue(exit_on_false=True)

	if dry_run:
		console.styled_print("QuantCrypt would have removed these directories: ")
		console.pretty_print([p.as_posix() for p in remove_paths.values()])
	else:  # pragma: no cover
		for path in remove_paths.values():
			shutil.rmtree(path, ignore_errors=True)
		console.print_success()
