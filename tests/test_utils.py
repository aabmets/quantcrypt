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
from typing import cast, Callable
from quantcrypt.internal import utils
from quantcrypt.errors import InvalidArgsError


def test_b64_helper_func():
	assert utils.b64(b'abcdefg') == "YWJjZGVmZw=="
	assert utils.b64("YWJjZGVmZw==") == b'abcdefg'
	with pytest.raises(InvalidArgsError):
		utils.b64(cast(13, bytes))


def test_input_validator():
	decorator = utils.input_validator()
	assert isinstance(decorator, Callable)


def test_search_upwards():
	path = utils.search_upwards(__file__, "tests")
	assert isinstance(path, Path)
	assert path == Path(__file__).parent


def test_search_upwards_error():
	with pytest.raises(RuntimeError):
		bad_path = secrets.token_hex()
		utils.search_upwards(__file__, bad_path)
