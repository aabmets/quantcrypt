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
import platform
from typing import Callable, Type, Annotated
from pydantic import Field, ConfigDict, validate_call
from pathlib import (
	PureWindowsPath,
	PurePosixPath,
	Path
)
from . import errors


__all__ = [
	"b64",
	"input_validator",
	"search_upwards",
	"is_path_relative",
	"annotated_bytes"
]


def b64(data: str | bytes) -> str | bytes:
	try:
		if isinstance(data, str):
			return base64.b64decode(data.encode("utf-8"))
		elif isinstance(data, bytes):
			return base64.b64encode(data).decode("utf-8")
		raise errors.InvalidArgsError
	except (UnicodeError, binascii.Error):
		raise errors.InvalidArgsError


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


def is_path_relative(path: Path | str) -> bool:
	match platform.system():  # pragma: no cover
		case "Linux" | "Darwin":
			return not PurePosixPath(path).is_absolute()
		case "Windows":
			return not PureWindowsPath(path).is_absolute()


def annotated_bytes(min_size: int = None, max_size: int = None, equal_to: int = None) -> Type[bytes]:
	return Annotated[bytes, Field(
		min_length=equal_to or min_size,
		max_length=equal_to or max_size,
		strict=True
	)]
