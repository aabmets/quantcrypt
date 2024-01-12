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
import base64
import binascii
from pathlib import Path
from typing import Callable
from pydantic import ConfigDict, validate_call
from .errors import InvalidArgsError


__all__ = ["b64", "input_validator", "search_upwards"]


def b64(data: str | bytes) -> str | bytes:
	try:
		if isinstance(data, str):
			return base64.b64decode(data.encode("utf-8"))
		elif isinstance(data, bytes):
			return base64.b64encode(data).decode("utf-8")
		raise InvalidArgsError
	except (UnicodeError, binascii.Error):
		raise InvalidArgsError


def input_validator() -> Callable:
	return validate_call(config=ConfigDict(
		arbitrary_types_allowed=True,
		validate_return=True
	))


def search_upwards(from_path: str, for_path: str) -> Path | None:
	current_path = Path(from_path)
	while current_path != current_path.parent:
		new_path = current_path / for_path
		if new_path.exists():
			return new_path
		current_path = current_path.parent
	raise RuntimeError(f"Fatal Error! Path not found: {for_path}")
