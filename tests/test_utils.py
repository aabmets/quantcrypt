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

import pytest
import secrets
from pathlib import Path
from pydantic import fields
from typing import cast, Callable
from annotated_types import MinLen, MaxLen
from quantcrypt.internal import errors
from quantcrypt.internal import utils


def test_b64_helper_func():
	assert utils.b64(b'abcdefg') == "YWJjZGVmZw=="
	assert utils.b64("YWJjZGVmZw==") == b'abcdefg'
	with pytest.raises(errors.InvalidArgsError):
		utils.b64(cast(13, bytes))
	with pytest.raises(errors.InvalidArgsError):
		utils.b64("YWJjZGVmZw=")


def test_input_validator():
	decorator = utils.input_validator()
	assert isinstance(decorator, Callable)


def test_search_upwards():
	path = utils.search_upwards("tests", __file__)
	assert isinstance(path, Path)
	assert path == Path(__file__).parent


def test_search_upwards_error():
	pyproject_toml = utils.search_upwards("pyproject.toml")
	bad_path = secrets.token_hex()
	with pytest.raises(RuntimeError):
		utils.search_upwards(bad_path, __file__)
	with pytest.raises(RuntimeError):
		utils.search_upwards(bad_path, pyproject_toml.parent)


def test_annotated_bytes():
	typedef = utils.annotated_bytes(12, 34)
	info: fields.FieldInfo = vars(typedef)["__metadata__"][0]
	for cls in [MinLen, MaxLen]:
		assert any([isinstance(item, cls) for item in info.metadata])


def test_sha3_digest_file(tmp_path: Path):
	file_path = tmp_path / "sample.txt"
	file_path.write_text("x" * 1024**2)
	counter = []

	utils.sha3_digest_file(file_path)
	assert len(counter) == 0
	digest = utils.sha3_digest_file(
		file_path,
		lambda: counter.append(1)
	)
	assert isinstance(digest, bytes)
	assert len(digest) == 64
	assert len(counter) == 4
	assert utils.b64(digest).startswith("iWP48uUEEjzU5gXKK8FpzC10Bs")


def test_resolve_relpath():
	res = utils.resolve_relpath()
	assert res == Path.cwd()

	res = utils.resolve_relpath("asdfg")
	assert res == Path.cwd() / "asdfg"

	res = utils.resolve_relpath(Path.cwd() / "qwerty")
	assert res == Path.cwd() / "qwerty"
