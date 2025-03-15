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

import re
import string
import pytest
import secrets
import tempfile
from pathlib import Path


@pytest.fixture(name="alt_tmp_path", scope="function")
def fixture_alt_tmp_path(tmp_path) -> Path:
    base_path = Path(tempfile.gettempdir())

    match = re.search(r"/pytest-(\d+)/", tmp_path.as_posix())
    pytest_dir = "qc_pytest" + ('_' + match.group(1) if match else '')

    charset = string.ascii_letters + string.digits
    test_dir = ''.join([secrets.choice(charset) for _ in range(20)])

    test_path = base_path / pytest_dir / test_dir
    if test_path.exists():
        raise RuntimeError(f"Cannot reuse existing temp test path: {test_path}")

    test_path.mkdir(parents=True, exist_ok=True)
    return test_path
