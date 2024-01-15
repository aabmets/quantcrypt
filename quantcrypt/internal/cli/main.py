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
from rich.console import Console
from .models import PackageInfo
from . import utils


app = Typer(
    name="qclib",
    invoke_without_command=True,
    no_args_is_help=True
)
utils.add_typer_apps(app)


VersionAtd = Annotated[bool, Option(
    '--version', '-v', show_default=False,
    help='Print the package version to console and exit.'
)]
InfoAtd = Annotated[bool, Option(
    '--info', '-i', show_default=False,
    help='Print package info to console and exit.'
)]


@app.callback()
def main(version: VersionAtd = False, info: InfoAtd = False) -> None:
    if version:
        pkg_info = PackageInfo()
        print(pkg_info.Version)
    elif info:
        title_color = "[{}]".format("#ff5fff")
        key_color = "[{}]".format("#87d7d7")
        value_color = "[{}]".format("#ffd787")

        pkg_info = PackageInfo()
        console = Console(soft_wrap=True)
        console.print(f"{title_color}Package Info:")

        for k, v in pkg_info.toDict().items():
            k = f"{key_color}{k}"
            v = f"{value_color}{v}"
            console.print(f"{2 * ' '}{k}: {v}")
        console.print('')
