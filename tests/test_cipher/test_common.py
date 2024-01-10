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
from pydantic import ValidationError
from quantcrypt.internal.cipher.common import ChunkSizeKB, ChunkSizeMB
from quantcrypt.cipher import *
from quantcrypt.errors import *


def test_chunk_size_attributes():
    assert hasattr(ChunkSize, "KB")
    assert hasattr(ChunkSize, "MB")
    assert getattr(ChunkSize, "KB") == ChunkSizeKB
    assert getattr(ChunkSize, "MB") == ChunkSizeMB


def test_chunk_size_valid_input():
    for cs in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]:
        assert ChunkSize.KB(cs).get("value") == 1024 * cs
        assert ChunkSize.MB(cs).get("value") == 1024**2 * cs


def test_chunk_size_invalid_input():
    with pytest.raises(InvalidUsageError):
        ChunkSize()

    for num in range(512):
        if num in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]:
            continue
        with pytest.raises(ValidationError):
            ChunkSize.KB(num)
        with pytest.raises(ValidationError):
            ChunkSize.MB(num)
