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
from Cryptodome.Hash import SHA3_512
from pydantic import (
	Field, ConfigDict, validate_call
)
from typing import (
	BinaryIO, Generator, Optional,
	Callable, Type, Annotated
)
from pathlib import (
	PureWindowsPath,
	PurePosixPath,
	Path
)
from .chunksize import ChunkSize
from . import errors


__all__ = [
	"b64",
	"input_validator",
	"search_upwards",
	"annotated_bytes",
	"read_file_chunks",
	"sha3_digest_file",
	"resolve_relpath"
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


def annotated_bytes(
		min_size: int = None,
		max_size: int = None,
		equal_to: int = None
) -> Type[bytes]:
	return Annotated[bytes, Field(
		min_length=equal_to or min_size,
		max_length=equal_to or max_size,
		strict=True
	)]


def read_file_chunks(
		file: BinaryIO,
		chunk_size: int,
		callback: Optional[Callable] = None
) -> Generator[bytes, None, None]:
	while True:
		chunk = file.read(chunk_size)
		if not chunk:
			break
		elif callback:
			callback()
		yield chunk


def sha3_digest_file(file_path: Path, callback: Optional[Callable] = None) -> bytes:
	sha3 = SHA3_512.new()
	file_size = file_path.stat().st_size
	chunk_size = ChunkSize.determine_from_data_size(file_size)

	with open(file_path, 'rb') as read_file:
		for chunk in read_file_chunks(read_file, chunk_size.value, callback):
			sha3.update(chunk)
		return sha3.digest()


def resolve_relpath(path: str | Path | None) -> Path:
	if path is None:
		path = Path('')

	match platform.system():  # pragma: no cover
		case "Windows":
			pure_path = PureWindowsPath(path)
		case _:
			pure_path = PurePosixPath(path)

	if pure_path.is_absolute():
		return Path(path)
	return (Path.cwd() / path).resolve()
