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
from pathlib import Path
from typing import Generator
from types import ModuleType
from typer import Typer
from .. import utils


__all__ = ["add_commands"]


def add_commands(app: Typer) -> Typer:
	for module in _find_command_modules():
		for _, obj in inspect.getmembers(module):
			if not isinstance(obj, Typer):
				continue
			app.add_typer(
				typer_instance=obj,
				name=obj.info.name
			)
	return app


def _find_command_modules() -> Generator[ModuleType, None, None]:
	package_path = utils.search_upwards(__file__, "__init__.py").parent
	import_dir = Path(__file__).with_name("commands")

	for filepath in import_dir.rglob("*.py"):
		relative_path = filepath.relative_to(package_path)
		module_path = '.'.join(relative_path.with_suffix('').parts)
		yield importlib.import_module(
			package=package_path.name,
			name=f'.{module_path}'
		)
