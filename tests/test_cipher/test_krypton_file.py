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
from dotmap import DotMap
from typing import Callable
from quantcrypt.cipher import KryptonFile, ChunkSize


def test_krypton_file_attributes():
	krypton = KryptonFile(b'x' * 64)

	assert hasattr(krypton, "encrypt")
	assert hasattr(krypton, "decrypt_to_file")
	assert hasattr(krypton, "decrypt_to_memory")
	assert hasattr(krypton, "read_file_header")

	assert isinstance(getattr(krypton, "encrypt"), Callable)
	assert isinstance(getattr(krypton, "decrypt_to_file"), Callable)
	assert isinstance(getattr(krypton, "decrypt_to_memory"), Callable)
	assert isinstance(getattr(krypton, "read_file_header"), Callable)


def test_krypton_file_enc_dec(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	krypton = KryptonFile(kfh.sk)
	krypton.encrypt(kfh.pt_file, kfh.ct_file)
	krypton.decrypt_to_file(kfh.ct_file, kfh.pt2_file)

	with kfh.pt2_file.open("rb") as file:
		pt2 = file.read()
	with kfh.ct_file.open("rb") as file:
		ct = file.read()

	assert pt2 == kfh.orig_pt
	assert ct != kfh.orig_pt


def test_krypton_file_enc_dec_callback(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	krypton = KryptonFile(kfh.sk, callback=kfh.callback)
	krypton.encrypt(kfh.pt_file, kfh.ct_file)
	assert sum(kfh.counter) == 4
	krypton.decrypt_to_file(kfh.ct_file, kfh.pt2_file)
	assert sum(kfh.counter) == 8


def test_krypton_file_read_header(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	header = b'z' * 32
	krypton = KryptonFile(kfh.sk)
	krypton.encrypt(kfh.pt_file, kfh.ct_file, header=header)
	header2 = krypton.read_file_header(kfh.ct_file)
	assert header2 == header

	with pytest.raises(FileNotFoundError):
		krypton.read_file_header(Path("asdfgh"))


def test_krypton_file_enc_dec_header(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers
	header = b'z' * 32

	krypton = KryptonFile(kfh.sk)
	krypton.encrypt(kfh.pt_file, kfh.ct_file, header=header)
	header2 = krypton.decrypt_to_file(kfh.ct_file, kfh.pt2_file)
	assert header2 == header


def test_krypton_file_enc_dec_into_memory(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	krypton = KryptonFile(kfh.sk)
	krypton.encrypt(kfh.pt_file, kfh.ct_file)
	dec_data = krypton.decrypt_to_memory(kfh.ct_file)
	assert dec_data.plaintext == kfh.orig_pt


def test_krypton_file_enc_dec_chunk_size_override(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	krypton = KryptonFile(kfh.sk, chunk_size=ChunkSize.KB(1), callback=kfh.callback)
	krypton.encrypt(kfh.pt_file, kfh.ct_file)
	assert sum(kfh.counter) == 16
	dec_data = krypton.decrypt_to_memory(kfh.ct_file)
	assert sum(kfh.counter) == 32
	assert dec_data.plaintext == kfh.orig_pt


def test_krypton_file_enc_dec_errors(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kfh.ct_file.touch()
	kfh.pt2_file.touch()

	krypton = KryptonFile(kfh.sk)
	with pytest.raises(FileNotFoundError):
		krypton.encrypt(Path("asdfg"), kfh.ct_file)
	with pytest.raises(FileNotFoundError):
		krypton.decrypt_to_file(Path("asdfg"), kfh.pt2_file)
	with pytest.raises(FileNotFoundError):
		krypton.decrypt_to_memory(Path("asdfg"))
