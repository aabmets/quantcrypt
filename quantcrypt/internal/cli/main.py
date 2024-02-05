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
from .info import PackageInfo
from . import utils, console


app = utils.add_commands(Typer(
	name="qclib",
	invoke_without_command=True,
	no_args_is_help=True
))


VersionAtd = Annotated[bool, Option(
	'--version', '-v', show_default=False,
	help="Prints package version to the console and exits."
)]
InfoAtd = Annotated[bool, Option(
	'--info', '-i', show_default=False,
	help="Prints project info to the console and exits."
)]


@app.callback()
def main(version: VersionAtd = False, info: InfoAtd = False) -> None:
	if version and info:
		a, b = [f"[bold turquoise2]--{kw}[/]" for kw in ["version", "info"]]
		console.raise_error(f"Cannot use {a} and {b} options simultaneously.")
	elif version or info:
		if version:
			print(PackageInfo().Version)
		else:
			title_color = "[{}]".format("#ff5fff")
			key_color = "[{}]".format("#87d7d7")
			value_color = "[{}]".format("#ffd787")

			console.styled_print(f"{title_color}Package Info:")
			for k, v in PackageInfo().toDict().items():
				k = f"{key_color}{k}"
				v = f"{value_color}{v}"
				console.styled_print(f"{2 * ' '}{k}: {v}")
			console.styled_print('')
