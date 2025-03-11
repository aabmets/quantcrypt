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
import typing as t
from pydantic import ValidationError
from quantcrypt.internal import errors
from quantcrypt.internal.chunksize import (
    ChunkSize, ChunkSizeKB, ChunkSizeMB, KBLiteral, MBLiteral
)


def test_chunk_size_attributes():
    assert hasattr(ChunkSize, "KB")
    assert hasattr(ChunkSize, "MB")
    assert getattr(ChunkSize, "KB") == ChunkSizeKB
    assert getattr(ChunkSize, "MB") == ChunkSizeMB


def test_chunk_size_valid_input():
    for x in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
        assert ChunkSize.KB(t.cast(KBLiteral, x)).value == 1024 * x
    for x in range(0, 10):
        x += 1
        assert ChunkSize.MB(t.cast(MBLiteral, x)).value == 1024**2 * x


def test_chunk_size_invalid_input():
    with pytest.raises(errors.InvalidUsageError):
        ChunkSize()

    with pytest.raises(ValidationError):
        ChunkSize.KB(t.cast(KBLiteral, -1))
    with pytest.raises(ValidationError):
        ChunkSize.KB(t.cast(KBLiteral, 0))

    with pytest.raises(ValidationError):
        ChunkSize.MB(t.cast(MBLiteral, -1))
    with pytest.raises(ValidationError):
        ChunkSize.MB(t.cast(MBLiteral, 0))


def test_determine_file_chunk_size():
    kilo_bytes = 1024
    mega_bytes = kilo_bytes * 1024

    for x, y in [(4, 1), (16, 4), (64, 16), (256, 64), (1024, 256)]:
        _cs = ChunkSize.determine_from_data_size(kilo_bytes * x)
        assert _cs.value == kilo_bytes * y

    for x in range(0, 10):
        x += 1
        _cs = ChunkSize.determine_from_data_size(mega_bytes * x * 100)
        assert _cs.value == mega_bytes * x

    _cs = ChunkSize.determine_from_data_size(mega_bytes * 11 * 100)
    assert _cs.value == mega_bytes * 10
