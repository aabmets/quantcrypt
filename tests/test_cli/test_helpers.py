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
from pathlib import Path
from quantcrypt.internal.cli.commands import helpers as hlp


def test_resolve_optional_file():
	path = hlp.resolve_optional_file(
		optional_file=None,
		from_file=Path("asdfg.bin"),
		new_suffix=".txt"
	)
	assert path.name == "asdfg.txt"


def test_resolve_directory(tmp_path: Path):
	tmp_file = tmp_path / "file.txt"
	tmp_file.touch()

	with pytest.raises(SystemExit, match='1'):
		hlp.resolve_directory(tmp_file.as_posix())

	sub_dir = tmp_path / "sub/dir"
	hlp.resolve_directory(sub_dir.as_posix())
	assert sub_dir.exists()


def test_process_paths(tmp_path: Path):
	key_file = tmp_path / "key_file.txt"
	in_file = tmp_path / "in_file.txt"

	with pytest.raises(SystemExit, match='1'):
		hlp.process_paths(
			key_file=key_file.as_posix(),
			in_file=in_file.as_posix(),
			out_file="",
			new_suffix=".suf"
		)
