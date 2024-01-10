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
from typing import cast
from quantcrypt.internal import utils
from quantcrypt.errors import InvalidArgsError


def test_b64_helper_func():
	assert utils.b64(b'abcdefg') == "YWJjZGVmZw=="
	assert utils.b64("YWJjZGVmZw==") == b'abcdefg'
	with pytest.raises(InvalidArgsError):
		utils.b64(cast(13, bytes))
