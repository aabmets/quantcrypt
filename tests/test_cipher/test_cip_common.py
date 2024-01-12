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
from typing import Literal, cast
from pydantic import ValidationError
from quantcrypt.internal.cipher.common import ChunkSizeKB, ChunkSizeMB
from quantcrypt.errors import InvalidUsageError
from quantcrypt.cipher import ChunkSize


ValidValue = Literal[1, 2, 4, 8, 16, 32, 64, 128, 256, 512]


def test_chunk_size_attributes():
    assert hasattr(ChunkSize, "KB")
    assert hasattr(ChunkSize, "MB")
    assert getattr(ChunkSize, "KB") == ChunkSizeKB
    assert getattr(ChunkSize, "MB") == ChunkSizeMB


def test_chunk_size_valid_input():
    for cs in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]:
        cast_cs = cast(ValidValue, cs)
        assert ChunkSize.KB(cast_cs).get("value") == 1024 * cs
        assert ChunkSize.MB(cast_cs).get("value") == 1024**2 * cs


def test_chunk_size_invalid_input():
    with pytest.raises(InvalidUsageError):
        ChunkSize()

    for num in range(512):
        if num in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]:
            continue
        cast_num = cast(ValidValue, num)
        with pytest.raises(ValidationError):
            ChunkSize.KB(cast_num)
        with pytest.raises(ValidationError):
            ChunkSize.MB(cast_num)
