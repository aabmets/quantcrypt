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
from typing import Callable
from pydantic import ValidationError
from quantcrypt.cipher import Krypton, ChunkSize
from quantcrypt.internal.cipher import errors


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
