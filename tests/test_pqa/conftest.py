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
from abc import ABC, abstractmethod
from typing import Type, cast
from pydantic import ValidationError
from quantcrypt.internal import errors, pqclean
from quantcrypt.internal import constants as const
from quantcrypt.internal.pqa.base_dss import BaseDSS
from quantcrypt.internal.pqa.base_kem import BaseKEM


class BaseAlgorithmTester(ABC):
	@classmethod
	@abstractmethod
	def run_tests(cls, alt_tmp_path: Path, pqa_class: Type[BaseDSS | BaseKEM]) -> None: ...

	@staticmethod
	def notify(pqa_instance: BaseDSS | BaseKEM, msg: str) -> None:
		name = pqa_instance.armor_name()
		variant = pqa_instance.variant.value
		print(f"{msg} of {variant} {name}")

	@staticmethod
	def invalid_keys(valid_key: bytes) -> list[bytes]:
		str_key = cast(bytes, valid_key.decode(errors="replace"))
		return [str_key, valid_key[:-1], valid_key + b'0']

	@staticmethod
	def invalid_messages(valid_message: bytes) -> list[bytes]:
		str_msg = cast(bytes, valid_message.decode(errors="replace"))
		return [str_msg, b'']

	@staticmethod
	def invalid_signatures(valid_signature: bytes, max_size: int) -> list[bytes]:
		str_sig = cast(bytes, valid_signature.decode(errors="replace"))
		extra = b'0' * (max_size - len(valid_signature) + 1)
		return [str_sig, valid_signature + extra]

	@staticmethod
	def invalid_ciphertexts(valid_ciphertext: bytes) -> list[bytes]:
		str_txt = cast(bytes, valid_ciphertext.decode(errors="replace"))
		return [str_txt, valid_ciphertext[:-1], valid_ciphertext + b'0']

	@staticmethod
	def get_pqa_instances(pqa_class: Type[BaseDSS | BaseKEM]) -> list[BaseDSS | BaseKEM]:
		instances: list[BaseDSS | BaseKEM] = []
		spec = pqa_class.get_spec()
		for variant in const.PQAVariant.members():  # type: const.PQAVariant
			if "CODECOV" in os.environ and variant != const.PQAVariant.REF:
				continue
			path, flags = pqclean.check_platform_support(spec, variant)
			if path is not None and flags is not None:
				inst = pqa_class(variant, allow_fallback=False)
				instances.append(inst)
		return instances

	@classmethod
	def run_armor_success_tests(cls, pqa_instance: BaseDSS | BaseKEM) -> None:
		cls.notify(pqa_instance, "Testing armor success")
		public_key, secret_key = pqa_instance.keygen()

		apk = pqa_instance.armor(public_key)
		assert apk.startswith("-----BEGIN")
		assert apk.endswith("PUBLIC KEY-----")

		ask = pqa_instance.armor(secret_key)
		assert ask.startswith("-----BEGIN")
		assert ask.endswith("SECRET KEY-----")

		pkb = pqa_instance.dearmor(apk)
		assert pkb == public_key

		skb = pqa_instance.dearmor(ask)
		assert skb == secret_key


	@classmethod
	def run_armor_failure_tests(cls, pqa_instance: BaseDSS | BaseKEM) -> None:
		cls.notify(pqa_instance, "Testing armor failure")
		public_key, secret_key = pqa_instance.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				pqa_instance.armor(cast(key(), bytes))

		if "SPHINCS" in pqa_instance.armor_name():
			return  # key size parameters are broken in C code

		for key in cls.invalid_keys(public_key):
			with pytest.raises(errors.PQAKeyArmorError):
				pqa_instance.armor(key)

		for key in cls.invalid_keys(secret_key):
			with pytest.raises(errors.PQAKeyArmorError):
				pqa_instance.armor(key)

	@classmethod
	def run_dearmor_failure_tests(cls, pqa_instance: BaseDSS | BaseKEM) -> None:
		cls.notify(pqa_instance, "Testing dearmor failure")
		public_key, secret_key = pqa_instance.keygen()

		for key in [str, int, float, list, dict, tuple, set]:
			with pytest.raises(ValidationError):
				pqa_instance.dearmor(cast(key(), bytes))

		if "SPHINCS" in pqa_instance.armor_name():
			return  # key size parameters are broken in C code

		def _reuse_tests(data: list[str]):
			center = len(data) // 2

			with pytest.raises(errors.PQAKeyArmorError):
				copy = data.copy()
				copy.pop(center)
				pqa_instance.dearmor('\n'.join(copy))

			with pytest.raises(errors.PQAKeyArmorError):
				copy = data.copy()
				copy.insert(1, data[1])
				pqa_instance.dearmor('\n'.join(copy))

			with pytest.raises(errors.PQAKeyArmorError):
				copy = data.copy()
				line = copy.pop(center)[:-1] + '!'
				copy.insert(center, line)
				pqa_instance.dearmor('\n'.join(copy))

			with pytest.raises(errors.PQAKeyArmorError):
				pqa_instance.dearmor("")

		apk = pqa_instance.armor(public_key).split('\n')
		_reuse_tests(apk)

		ask = pqa_instance.armor(secret_key).split('\n')
		_reuse_tests(ask)
