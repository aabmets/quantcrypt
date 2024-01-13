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
import site
from pathlib import Path
from dotmap import DotMap
from typing import Annotated
from typer import Typer, Option
from rich.console import Console
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
def main(version: VersionAtd = False, info: InfoAtd = False):
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


class PackageInfo(DotMap):
    _PACKAGE_NAME = "quantcrypt"

    def __init__(self) -> None:
        super().__init__()

        for site_dir in site.getsitepackages():
            if "site-packages" not in site_dir:
                continue

            for child in Path(site_dir).iterdir():
                is_self_pkg = child.name.startswith(self._PACKAGE_NAME)
                if not is_self_pkg or child.suffix != '.dist-info':
                    continue

                meta = child / 'METADATA'
                if meta.is_file():
                    with meta.open("r") as file:
                        lines = file.readlines()
                    self._set_fields(lines)

    def _set_fields(self, lines: list[str]) -> None:
        fields = ["Name", "Version", "Summary", "License", "Author"]
        for line in lines:
            line = line.strip()
            if line == '':
                break
            k, v = line.split(':', maxsplit=1)
            v = v.strip()
            if k in fields:
                setattr(self, k, v)
            if v.startswith('Repository'):
                k, v = v.split(', ')
                k = "Homepage"
                setattr(self, k, v)
