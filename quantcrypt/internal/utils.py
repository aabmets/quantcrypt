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

import pickle
import base64
import binascii
import typing as t
from pathlib import Path
from functools import lru_cache
from Cryptodome.Hash import SHA3_512
from pydantic import Field, ConfigDict, validate_call
from quantcrypt.internal.chunksize import ChunkSize
from quantcrypt.internal import errors


__all__ = [
	"b64",
	"b64pickle",
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


T = t.TypeVar("T")
def b64pickle(obj: T | str) -> T | str:
	if isinstance(obj, str):
		return pickle.loads(b64(obj))
	return b64(pickle.dumps(obj))


def input_validator() -> t.Callable:
	return validate_call(config=ConfigDict(
		arbitrary_types_allowed=True,
		validate_return=True
	))


@lru_cache
def search_upwards(for_path: str | Path, from_path: str | Path = __file__) -> Path:
	current_path = Path(from_path).parent.resolve()
	while current_path != current_path.parent:
		search_path = current_path / for_path
		if search_path.exists():
			return search_path
		elif (current_path / ".git").exists():
			break
		current_path = current_path.parent
	raise RuntimeError(f"Cannot find path '{for_path}' upwards from '{from_path}'")


def annotated_bytes(
		min_size: int = None,
		max_size: int = None,
		equal_to: int = None
) -> t.Type[bytes]:
	return t.Annotated[bytes, Field(
		min_length=equal_to or min_size,
		max_length=equal_to or max_size,
		strict=True
	)]


def read_file_chunks(
		file: t.BinaryIO,
		chunk_size: int,
		callback: t.Callable | None = None
) -> t.Generator[bytes, None, None]:
	while True:
		chunk = file.read(chunk_size)
		if not chunk:
			break
		elif callback:
			callback()
		yield chunk


def sha3_digest_file(file_path: Path, callback: t.Callable | None = None) -> bytes:
	sha3 = SHA3_512.new()
	file_size = file_path.stat().st_size
	chunk_size = ChunkSize.determine_from_data_size(file_size)

	with open(file_path, 'rb') as read_file:
		for chunk in read_file_chunks(read_file, chunk_size.value, callback):
			sha3.update(chunk)
		return sha3.digest()


def resolve_relpath(path: str | Path | None = None) -> Path:
	_path = Path(path or '')
	if _path.is_absolute():
		return Path(_path)
	return (Path.cwd() / _path).resolve()
