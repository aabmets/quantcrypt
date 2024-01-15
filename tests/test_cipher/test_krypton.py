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
from typing import Callable
from pydantic import ValidationError
from quantcrypt.errors import InvalidArgsError
from quantcrypt.cipher import Krypton, ChunkSize
from quantcrypt.internal.cipher import errors


@pytest.fixture(name="file_data")
def fixture_file_data(tmp_path: Path) -> DotMap:
    orig_pt = os.urandom(1024 * 16)
    pt_file = tmp_path / "test_file.bin"
    ct_file = tmp_path / "test_file.enc"
    pt2_file = tmp_path / "test_file2.bin"

    with pt_file.open("wb") as file:
        file.write(orig_pt)

    return DotMap(
        sk=b'x' * 64,
        orig_pt=orig_pt,
        pt_file=pt_file,
        ct_file=ct_file,
        pt2_file=pt2_file
    )


def test_krypton_attributes():
    krypton = Krypton(
        secret_key=b'x' * 64,
        context=b'z' * 16,
        chunk_size=ChunkSize.KB(1)
    )
    assert isinstance(krypton, Krypton), \
        f"Expected an instance of Krypton, but received {type(krypton)}"

    for method in [
        "flush",
        "begin_encryption",
        "encrypt",
        "finish_encryption",
        "begin_decryption",
        "decrypt",
        "finish_decryption"
    ]:
        assert hasattr(krypton, method)
        assert isinstance(getattr(krypton, method), Callable)


def test_krypton_invalid_key_arg():
    with pytest.raises(ValidationError):
        Krypton(b'x' * 63)
    with pytest.raises(ValidationError):
        Krypton(b'x' * 65)


def test_krypton_basic_workflow():
    secret_key = b'x' * 64
    plaintext = b'abcd' * 25
    header = b'z' * 16

    k1 = Krypton(secret_key)
    k1.begin_encryption(header)
    ct = k1.encrypt(plaintext)
    digest = k1.finish_encryption()

    assert len(ct) == 100

    k2 = Krypton(secret_key)
    k2.begin_decryption(digest, header)
    pt = k2.decrypt(ct)
    k2.finish_decryption()

    assert pt == plaintext


def test_krypton_chunked_workflow():
    secret_key = b'x' * 64
    plaintext = b'abcd' * 25
    header = b'z' * 16

    k1 = Krypton(secret_key, chunk_size=ChunkSize.KB(1))
    k1.begin_encryption(header)
    ciphertext = k1.encrypt(plaintext)
    digest = k1.finish_encryption()

    assert len(ciphertext) == 1024 + 1

    k2 = Krypton(secret_key, chunk_size=ChunkSize.KB(1))
    k2.begin_decryption(digest, header)
    pt = k2.decrypt(ciphertext)
    k2.finish_decryption()

    assert pt == plaintext


def test_krypton_chunked_errors():
    secret_key = b'x' * 64
    plaintext = b'abcd' * 25

    k1 = Krypton(secret_key, chunk_size=ChunkSize.KB(1))
    k1.begin_encryption()
    with pytest.raises(errors.CipherChunkSizeError):
        k1.encrypt(b'x' * 1025)
    ciphertext = k1.encrypt(plaintext)
    digest = k1.finish_encryption()

    k2 = Krypton(secret_key, chunk_size=ChunkSize.KB(1))
    k2.begin_decryption(digest)
    with pytest.raises(errors.CipherChunkSizeError):
        k2.decrypt(b'x' * 1024)
    with pytest.raises(errors.CipherChunkSizeError):
        k2.decrypt(b'x' * 1026)
    with pytest.raises(errors.CipherPaddingError):
        k2.decrypt(ciphertext[::-1])


def test_krypton_invalid_digest():
    secret_key = b'x' * 64
    header = b'z' * 16

    k1 = Krypton(secret_key)
    k1.begin_encryption(header)
    digest = k1.finish_encryption()

    digest = digest[::-1]  # Corrupt digest

    k2 = Krypton(secret_key)
    with pytest.raises(errors.CipherVerifyError):
        k2.begin_decryption(digest, header)


def test_krypton_invalid_ciphertext():
    secret_key = b'x' * 64
    plaintext = b'abcd' * 25
    header = b'z' * 16

    k1 = Krypton(secret_key)
    k1.begin_encryption(header)
    ciphertext = k1.encrypt(plaintext)
    digest = k1.finish_encryption()

    ciphertext = ciphertext[::-1]  # Corrupt ciphertext

    k2 = Krypton(secret_key)
    k2.begin_decryption(digest, header)
    k2.decrypt(ciphertext)
    with pytest.raises(errors.CipherVerifyError):
        k2.finish_decryption()


def test_krypton_invalid_state_error():
    k = Krypton(b'x' * 64)

    k.begin_encryption()
    with pytest.raises(errors.CipherStateError):
        k.begin_decryption(b'x' * 160)
    with pytest.raises(errors.CipherStateError):
        k.decrypt(b'')
    with pytest.raises(errors.CipherStateError):
        k.finish_decryption()

    digest = k.finish_encryption()
    k.flush()

    k.begin_decryption(digest)
    with pytest.raises(errors.CipherStateError):
        k.begin_encryption()
    with pytest.raises(errors.CipherStateError):
        k.encrypt(b'')
    with pytest.raises(errors.CipherStateError):
        k.finish_encryption()


def test_krypton_file_enc_dec(file_data: DotMap):
    Krypton.encrypt_file(file_data.sk, file_data.pt_file, file_data.ct_file)
    Krypton.decrypt_file(file_data.sk, file_data.ct_file, file_data.pt2_file)

    with file_data.pt2_file.open("rb") as file:
        pt2 = file.read()
    with file_data.ct_file.open("rb") as file:
        ct = file.read()

    assert pt2 == file_data.orig_pt
    assert ct != file_data.orig_pt


def test_krypton_file_enc_dec_callback(file_data: DotMap):
    counters = list(), list()

    def callback(i):
        def _cb():
            counters[i].append(1)
        return _cb

    Krypton.encrypt_file(
        file_data.sk, file_data.pt_file, file_data.ct_file,
        callback=callback(0)
    )
    Krypton.decrypt_file(
        file_data.sk, file_data.ct_file, file_data.pt2_file,
        callback=callback(1)
    )

    assert sum(counters[0]) == 4
    assert sum(counters[1]) == 4


def test_krypton_file_enc_dec_into_memory(file_data: DotMap):
    Krypton.encrypt_file(file_data.sk, file_data.pt_file, file_data.ct_file)
    pt2 = Krypton.decrypt_file(
        file_data.sk, file_data.ct_file, file_data.pt2_file,
        into_memory=True
    )
    assert pt2 == file_data.orig_pt


def test_krypton_file_enc_dec_chunk_size_override(file_data: DotMap):
    counter = list()

    def callback():
        counter.append(1)

    Krypton.encrypt_file(
        file_data.sk, file_data.pt_file, file_data.ct_file,
        chunk_size=ChunkSize.KB(1)
    )
    pt2 = Krypton.decrypt_file(
        file_data.sk, file_data.ct_file, file_data.pt2_file,
        callback=callback, into_memory=True
    )
    assert sum(counter) == 16
    assert pt2 == file_data.orig_pt


def test_krypton_file_enc_dec_errors(tmp_path: Path):
    valid_sk = b'x' * 64
    tmp_file = tmp_path / "tmp.bin"
    tmp_file.touch()

    with pytest.raises(FileNotFoundError):
        Krypton.encrypt_file(valid_sk, Path("asdfg"), Path("qwerty"))
    with pytest.raises(FileNotFoundError):
        Krypton.decrypt_file(valid_sk, Path("asdfg"), Path("qwerty"))
    with pytest.raises(InvalidArgsError):
        Krypton.decrypt_file(valid_sk, tmp_file)
