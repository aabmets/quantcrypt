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
from quantcrypt.kdf import KKDF
from quantcrypt.internal.kdf import errors


def test_kkdf_instantiation_with_minimum_args():
	master_key = b'\x00' * 32
	result = KKDF(master=master_key)
	assert isinstance(result, tuple), \
		"Result should be a tuple"
	assert isinstance(result[0], bytes), \
		"All elements in result should be bytes"
	assert len(result) == 1, \
		"At least one key should be generated"


def test_kkdf_instantiation_with_all_params():
	result = KKDF(
		master=b'\x00' * 32,
		key_len=64,
		num_keys=2,
		salt=b'\x01' * 64,
		context=b'\x02' * 64
	)
	assert isinstance(result, tuple), \
		"Result should be a tuple"
	assert len(result) == 2, \
		"Number of keys in result should match num_keys"
	assert all(len(key) == 64 for key in result), \
		"Each key should have length equal to key_len"
	assert all(isinstance(key, bytes) for key in result), \
		"All elements in result should be bytes"
	assert len({key for key in result}) == len(result), \
		"All keys should be unique"


def test_kkdf_short_master_key():
	with pytest.raises(ValueError):
		KKDF(
			master=b'\x00' * 31,  # Master key is only 31 bytes long
			key_len=32,
			num_keys=1,
			salt=None,
			context=None
		)


def test_kkdf_invalid_key_len():
	# Test with key_len less than 32
	with pytest.raises(ValueError):
		KKDF(
			master=b'\x00' * 32,
			key_len=31,  # Invalid key_len
			num_keys=1,
			salt=None,
			context=None
		)
	# Test with key_len greater than 1024
	with pytest.raises(ValueError):
		KKDF(
			master=b'\x00' * 32,
			key_len=1025,  # Invalid key_len
			num_keys=1,
			salt=None,
			context=None
		)


def test_kkdf_invalid_num_keys():
	# Test with num_keys less than 1
	with pytest.raises(ValueError):
		KKDF(
			master=b'\x00' * 32,
			key_len=32,
			num_keys=0,  # Invalid num_keys
			salt=None,
			context=None
		)
	# Test with num_keys greater than 2048
	with pytest.raises(ValueError):
		KKDF(
			master=b'\x00' * 32,
			key_len=32,
			num_keys=2049,  # Invalid num_keys
			salt=None,
			context=None
		)


def test_kkdf_custom_salt_and_context():
	# Test with specific salt and context
	result_with_custom_salt_and_context = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1,
		salt=b'\x01' * 64,  # Custom salt
		context=b'\x02' * 64  # Custom context
	)
	# Test with default salt and context (None)
	result_with_default_salt_and_context = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1,
		salt=None,
		context=None
	)
	assert result_with_custom_salt_and_context != result_with_default_salt_and_context, \
		"Outputs should differ when using custom salt and context versus defaults"


def test_kkdf_max_allowed_entropy():
	KKDF(
		master=b'\x00' * 32,
		key_len=64,
		num_keys=1024
	)


def test_kkdf_key_len_entropy_limit_error():
	with pytest.raises(errors.KDFOutputLimitError):
		KKDF(
			master=b'\x00' * 32,
			key_len=65,  # Key length set to exceed the entropy limit when multiplied by num_keys
			num_keys=1024
		)


def test_kkdf_num_keys_entropy_limit_error():
	with pytest.raises(errors.KDFOutputLimitError):
		KKDF(
			master=b'\x00' * 32,
			key_len=64,
			num_keys=1025  # Number of keys set to exceed the entropy limit when multiplied by key_len
		)


def test_kkdf_unique_keys_different_master():
	base = b'\x01' * 31
	result_1 = KKDF(
		master=base + b'\x02',
		key_len=32,
		num_keys=1
	)
	result_2 = KKDF(
		master=base + b'\x03',
		key_len=32,
		num_keys=1
	)
	assert result_1 != result_2, \
		"Generated keys should be different for different master keys"


def test_kkdf_different_salt_produces_different_keys():
	base = b'\x01' * 63
	result_with_salt_context_1 = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1,
		salt=base + b'\x02',
		context=b'\x01' * 64
	)
	result_with_salt_context_2 = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1,
		salt=base + b'\x03',
		context=b'\x01' * 64
	)
	assert result_with_salt_context_1 != result_with_salt_context_2, \
		"Changing salt should produce different keys"


def test_kkdf_different_context_produces_different_keys():
	base = b'\x01' * 63
	result_with_salt_context_1 = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1,
		salt=b'\x01' * 64,
		context=base + b'\x02'
	)
	result_with_salt_context_2 = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1,
		salt=b'\x01' * 64,
		context=base + b'\x03'
	)
	assert result_with_salt_context_1 != result_with_salt_context_2, \
		"Changing context should produce different keys"


def test_kkdf_output_structure_and_length():
	num_keys_test = 5
	result = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=num_keys_test
	)
	assert isinstance(result, tuple), \
		"Output should be a tuple"
	assert len(result) == num_keys_test, \
		"Length of output should match num_keys"
	assert all(isinstance(key, bytes) for key in result), \
		"Each element in the output should be of type bytes"


def test_kkdf_key_length_in_output():
	key_length_test = 64
	result = KKDF(
		master=b'\x00' * 32,
		key_len=key_length_test,
		num_keys=3
	)
	assert all(len(key) == key_length_test for key in result), \
		"Each key in the output should have a length equal to key_len"


def test_kkdf_handling_none_salt_context():
	result_with_none_salt_context = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1,
		salt=None,
		context=None
	)
	result_with_default_salt_context = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1
	)
	assert result_with_none_salt_context == result_with_default_salt_context, \
		"Outputs should be identical when salt and context are None or defaults"


def test_kkdf_smallest_valid_key_len():
	result = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1
	)
	assert len(result[0]) == 32, \
		"The generated key should have the smallest valid length of 32 bytes"


def test_kkdf_valid_master_key_length():
	result = KKDF(
		master=b'\x00' * 32,
		key_len=32,
		num_keys=1
	)
	assert isinstance(result, tuple) and len(result) > 0, \
		"KKDF should accept a 32-byte master key and generate at least one key"


def test_kkdf_iter_byte_incrementation():
	result_one_key = KKDF(
		master=b'\x00' * 32,
		key_len=64,
		num_keys=1
	)
	result_two_keys = KKDF(
		master=b'\x00' * 32,
		key_len=64,
		num_keys=2
	)
	assert result_one_key[0] != result_two_keys[1], \
		"Second key in two-key output should differ from single key output"
