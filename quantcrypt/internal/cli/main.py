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
from typer import Typer
from .info import PackageInfo
from . import utils, console


app = utils.add_commands(Typer(
    name="qclib",
    invoke_without_command=True,
    no_args_is_help=True
))


@app.command(name="version", help="Prints package version to the console and exits.")
def version():
    print(PackageInfo().Version)


@app.command(name="info", help="Pretty-prints package info to the console and exits.")
def info() -> None:
    title_color = "[{}]".format("#ff5fff")
    key_color = "[{}]".format("#87d7d7")
    value_color = "[{}]".format("#ffd787")

    console.styled_print(f"{title_color}Package Info:")
    for k, v in PackageInfo().toDict().items():
        k = f"{key_color}{k}"
        v = f"{value_color}{v}"
        console.styled_print(f"{2 * ' '}{k}: {v}")
    console.styled_print('')
