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
from quantcrypt.cipher import KryptonFile, ChunkSize


@pytest.fixture(name="helpers", scope="function")
def fixture_file_data(tmp_path: Path) -> DotMap:
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
		orig_pt=orig_pt,
		pt_file=pt_file,
		ct_file=ct_file,
		pt2_file=pt2_file,
		counter=counter,
		callback=callback
	)


def test_krypton_file_enc_dec(helpers: DotMap):
	krypton = KryptonFile(helpers.sk)

	krypton.encrypt(helpers.pt_file, helpers.ct_file)
	krypton.decrypt_to_file(helpers.ct_file, helpers.pt2_file)

	with helpers.pt2_file.open("rb") as file:
		pt2 = file.read()
	with helpers.ct_file.open("rb") as file:
		ct = file.read()

	assert pt2 == helpers.orig_pt
	assert ct != helpers.orig_pt


def test_krypton_file_enc_dec_callback(helpers: DotMap):
	krypton = KryptonFile(helpers.sk, callback=helpers.callback)
	krypton.encrypt(helpers.pt_file, helpers.ct_file)
	assert sum(helpers.counter) == 4
	krypton.decrypt_to_file(helpers.ct_file, helpers.pt2_file)
	assert sum(helpers.counter) == 8


def test_krypton_file_read_header(helpers: DotMap):
	header = b'z' * 32
	krypton = KryptonFile(helpers.sk)
	krypton.encrypt(helpers.pt_file, helpers.ct_file, header=header)
	header2 = krypton.read_file_header(helpers.ct_file)
	assert header2 == header

	with pytest.raises(FileNotFoundError):
		krypton.read_file_header(Path("asdfgh"))


def test_krypton_file_enc_dec_header(helpers: DotMap):
	header = b'z' * 32

	krypton = KryptonFile(helpers.sk)
	krypton.encrypt(helpers.pt_file, helpers.ct_file, header=header)
	header2 = krypton.decrypt_to_file(helpers.ct_file, helpers.pt2_file)
	assert header2 == header


def test_krypton_file_enc_dec_into_memory(helpers: DotMap):
	krypton = KryptonFile(helpers.sk)
	krypton.encrypt(helpers.pt_file, helpers.ct_file)
	dec_data = krypton.decrypt_into_memory(helpers.ct_file)
	assert dec_data.plaintext == helpers.orig_pt


def test_krypton_file_enc_dec_chunk_size_override(helpers: DotMap):
	krypton = KryptonFile(helpers.sk, chunk_size=ChunkSize.KB(1), callback=helpers.callback)
	krypton.encrypt(helpers.pt_file, helpers.ct_file)
	assert sum(helpers.counter) == 16
	dec_data = krypton.decrypt_into_memory(helpers.ct_file)
	assert sum(helpers.counter) == 32
	assert dec_data.plaintext == helpers.orig_pt


def test_krypton_file_enc_dec_errors(helpers: DotMap):
	krypton = KryptonFile(helpers.sk)
	with pytest.raises(FileNotFoundError):
		krypton.encrypt(Path("asdfg"), Path("qwerty"))
	with pytest.raises(FileNotFoundError):
		krypton.decrypt_to_file(Path("asdfg"), Path("qwerty"))
	with pytest.raises(FileNotFoundError):
		krypton.decrypt_into_memory(Path("asdfg"))
