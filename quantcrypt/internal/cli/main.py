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

import inspect
import importlib
from typer import Typer
from pathlib import Path
from typing import Generator
from types import ModuleType
from quantcrypt.internal import utils
from quantcrypt.internal.cli import annotations as atd
from quantcrypt.internal.cli.commands.info import PackageInfo


app = Typer(
    name="qclib",
    no_args_is_help=True,
    invoke_without_command=True
)


@app.callback()
def main(version: atd.Version = False) -> None:
    if version:
        print(PackageInfo().Version)


def find_command_modules() -> Generator[ModuleType, None, None]:
    package_path = utils.search_upwards("quantcrypt/__init__.py").parent
    import_dir = Path(__file__).with_name("commands")
    for filepath in import_dir.rglob("*.py"):
        relative_path = filepath.resolve().relative_to(package_path)
        module_path = '.'.join(relative_path.with_suffix('').parts)
        yield importlib.import_module(
            package=package_path.name,
            name=f'.{module_path}'
        )


for module in find_command_modules():
    for _, obj in inspect.getmembers(module):
        if isinstance(obj, Typer):
            app.add_typer(typer_instance=obj, name=obj.info.name)
