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
import os
import pytest
from pathlib import Path
from dotmap import DotMap


@pytest.fixture(scope="function")
def krypton_file_helpers(tmp_path: Path) -> DotMap:
	orig_pt = os.urandom(1024 * 16)
	pt_file = tmp_path / "test_file.bin"
	ct_file = tmp_path / "test_file.enc"
	pt2_file = tmp_path / "test_file2.bin"
	counter = list()

	with pt_file.open("wb") as file:
		file.write(orig_pt)

	def callback():
		counter.append(1)

	return DotMap(
		sk=b'x' * 64,
		tmp_path=tmp_path,
		orig_pt=orig_pt,
		pt_file=pt_file,
		ct_file=ct_file,
		pt2_file=pt2_file,
		counter=counter,
		callback=callback
	)
