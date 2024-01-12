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
import struct
from pydantic import Field
from typing import Annotated, Optional
from Cryptodome.Hash import KMAC256
from . import errors
from .. import utils


__all__ = ["KKDF"]


class KKDF:
	@utils.input_validator()
	def __new__(
			cls,
			master: Annotated[bytes, Field(min_length=32)],
			key_len: Annotated[int, Field(ge=32, le=1024)] = 32,
			num_keys: Annotated[int, Field(ge=1, le=2048)] = 1,
			salt: Annotated[Optional[bytes], Field()] = None,
			context: Annotated[Optional[bytes], Field()] = None
	) -> tuple[bytes, ...]:
		"""
		KKDF is a variant of HKDF, where the pseudorandom function
		HMAC is replaced with KMAC256, which is based on cSHAKE256,
		as defined in NIST SP 800-185. This implementation of KKDF
		only allows to derive 65536 bytes of keys from one master
		key, which is calculated with `key_len` * `num_keys`.

		:param master: The master secret key from which to derive new keys.
		:param key_len: The length of each derivative key in bytes.
		:param num_keys: The number of derivative keys to generate.
		:param salt: A cryptographically strong random number. It is
			recommended to generate a unique salt for each master key.
		:param context: A customization string, behaves like a namespace.
			Can be reused across multiple master keys and salt values.
		:raises - errors.KDFOutputLimitError: When `key_len` * `num_keys`
			is larger than the allowed maximum output of 65536 bytes for
			one master key.
		"""
		digest_size = 64
		entropy_limit = digest_size * 1024
		output_len = key_len * num_keys

		if output_len > entropy_limit:
			raise errors.KDFOutputLimitError(output_len)
		if salt is None:
			salt = b'\x00' * digest_size
		if context is None:
			context = b''

		# Step 1: extract
		prk = KMAC256.new(
			key=master,
			data=salt,
			mac_len=digest_size,
			custom=b''
		).digest()

		# Step 2: expand
		macs = b''
		iters = 1
		while len(macs) < output_len:
			iter_byte = struct.pack('H', iters)
			macs += KMAC256.new(
				key=prk,
				data=macs[-digest_size:] + iter_byte,
				mac_len=digest_size,
				custom=context
			).digest()
			iters += 1

		# Step 3: return
		out: list[bytes] = [
			macs[idx:idx + key_len]
			for idx in range(0, output_len, key_len)
		]
		return tuple(out)
