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
import timeit
import pytest
from pathlib import Path
from dotmap import DotMap
from typing import Callable
from quantcrypt.cipher import KryptonKEM, ChunkSize
from quantcrypt.kdf import KDFParams, MemCost
from quantcrypt.kem import Kyber


def test_krypton_kem_attributes():
	krypton = KryptonKEM(Kyber)

	assert hasattr(krypton, "encrypt")
	assert hasattr(krypton, "decrypt_to_file")
	assert hasattr(krypton, "decrypt_to_memory")

	assert isinstance(getattr(krypton, "encrypt"), Callable)
	assert isinstance(getattr(krypton, "decrypt_to_file"), Callable)
	assert isinstance(getattr(krypton, "decrypt_to_memory"), Callable)


def test_krypton_kem_enc_dec(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kem = Kyber()
	pk, sk = kem.keygen()
	krypton = KryptonKEM(Kyber, KDFParams(
		memory_cost=MemCost.MB(32),
		parallelism=8,
		time_cost=1,
		hash_len=64,
		salt_len=32
	))

	krypton.encrypt(pk, kfh.pt_file, kfh.ct_file)
	krypton.decrypt_to_file(sk, kfh.ct_file, kfh.pt2_file)

	with kfh.pt2_file.open("rb") as file:
		pt2 = file.read()
	with kfh.ct_file.open("rb") as file:
		ct = file.read()

	assert pt2 == kfh.orig_pt
	assert ct != kfh.orig_pt


def test_krypton_kem_output_file(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers
	os.chdir(kfh.tmp_path)

	kem = Kyber()
	pk, sk = kem.keygen()
	krypton = KryptonKEM(Kyber)
	setattr(krypton, "_testing", True)

	ct_file = kfh.pt_file.with_suffix(".kptn")

	krypton.encrypt(pk, kfh.pt_file)
	kfh.pt_file.unlink()
	krypton.decrypt_to_file(sk, ct_file)
	krypton.decrypt_to_file(sk, ct_file, kfh.pt2_file.name)

	with ct_file.open("rb") as file:
		ct = file.read()
	with kfh.pt_file.open("rb") as file:
		pt1 = file.read()
	with kfh.pt2_file.open("rb") as file:
		pt2 = file.read()

	assert ct != kfh.orig_pt
	assert pt1 == kfh.orig_pt
	assert pt2 == kfh.orig_pt


def test_krypton_kem_enc_dec_callback(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kem = Kyber()
	pk, sk = kem.keygen()
	krypton = KryptonKEM(Kyber, callback=kfh.callback)
	setattr(krypton, "_testing", True)

	krypton.encrypt(pk, kfh.pt_file, kfh.ct_file)
	assert sum(kfh.counter) == 4
	krypton.decrypt_to_file(sk, kfh.ct_file, kfh.pt2_file)
	assert sum(kfh.counter) == 8


def test_krypton_kem_enc_dec_into_memory(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kem = Kyber()
	pk, sk = kem.keygen()
	krypton = KryptonKEM(Kyber)
	setattr(krypton, "_testing", True)

	krypton.encrypt(pk, kfh.pt_file, kfh.ct_file)
	pt2 = krypton.decrypt_to_memory(sk, kfh.ct_file)
	assert pt2 == kfh.orig_pt


def test_krypton_kem_enc_dec_chunk_size_override(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kem = Kyber()
	pk, sk = kem.keygen()
	krypton = KryptonKEM(Kyber, chunk_size=ChunkSize.KB(1), callback=kfh.callback)
	setattr(krypton, "_testing", True)

	krypton.encrypt(pk, kfh.pt_file, kfh.ct_file)
	assert sum(kfh.counter) == 16
	pt2 = krypton.decrypt_to_memory(sk, kfh.ct_file)
	assert sum(kfh.counter) == 32
	assert pt2 == kfh.orig_pt


def test_krypton_kem_enc_dec_errors(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kem = Kyber()
	pk, sk = kem.keygen()
	krypton = KryptonKEM(Kyber)

	kfh.ct_file.touch()
	kfh.pt2_file.touch()

	with pytest.raises(FileNotFoundError):
		krypton.encrypt(pk, Path("asdfg"), kfh.ct_file)
	with pytest.raises(FileNotFoundError):
		krypton.decrypt_to_file(sk, Path("asdfg"), kfh.pt2_file)
	with pytest.raises(FileNotFoundError):
		krypton.decrypt_to_memory(sk, Path("asdfg"))


def test_krypton_kem_argon2_delay(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kem = Kyber()
	pk, sk = kem.keygen()
	krypton = KryptonKEM(Kyber)

	def test():
		krypton.encrypt(pk, kfh.pt_file, kfh.ct_file)

	def test2():
		krypton.decrypt_to_file(sk, kfh.ct_file, kfh.pt2_file)

	def test3():
		krypton.decrypt_to_memory(sk, kfh.ct_file)

	assert timeit.timeit(test, number=1) > 0.2
	assert timeit.timeit(test2, number=1) > 0.2
	assert timeit.timeit(test3, number=1) > 0.2


def test_krypton_kem_armored_keys(krypton_file_helpers: DotMap):
	kfh = krypton_file_helpers

	kem = Kyber()
	pk, sk = kem.keygen()

	krypton = KryptonKEM(Kyber, KDFParams(
		memory_cost=MemCost.MB(32),
		parallelism=8,
		time_cost=1,
		hash_len=64,
		salt_len=32
	))

	krypton.encrypt(kem.armor(pk), kfh.pt_file, kfh.ct_file)
	pt = krypton.decrypt_to_memory(kem.armor(sk), kfh.ct_file)
	assert pt == kfh.orig_pt
