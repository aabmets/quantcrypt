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
import re
from pathlib import Path
from dotmap import DotMap
from typing import Literal, Type
from dataclasses import dataclass
from quantcrypt.internal import utils
from quantcrypt.kem import BaseKEM, Kyber
from quantcrypt.dss import (
	BaseDSS,
	Dilithium,
	Falcon,
	FastSphincs,
	SmallSphincs
)


__all__ = [
	"resolve_optional_file",
	"process_paths",
	"determine_kem_class",
	"determine_dss_class"
]


@dataclass
class CommandPaths:
	key_file: Path
	data_file: Path
	target_file: Path


ExpKeyType = Literal["PUBLIC", "SECRET"]


def resolve_optional_file(optional_file: str | None, from_file: Path, new_suffix: str) -> Path:
	if optional_file is None:
		return from_file.with_suffix(new_suffix)
	return utils.resolve_relpath(optional_file)


def process_paths(key_file: str, data_file: str, target_file: str, new_suffix) -> CommandPaths:
	_key_file = utils.resolve_relpath(key_file)
	_data_file = utils.resolve_relpath(data_file)
	_target_file = resolve_optional_file(
		target_file, _data_file, new_suffix
	)
	return CommandPaths(
		key_file=_key_file,
		data_file=_data_file,
		target_file=_target_file
	)


def determine_kem_class(
		armored_key: str,
		expected_key_type: ExpKeyType
) -> Type[BaseKEM]:
	return _determine_pqa_class(
		armored_key,
		expected_key_type,
		supported_algos=dict(
			KYBER=Kyber
		),
		pqa_type="KEM"
	)


def determine_dss_class(
		armored_key: str,
		expected_key_type: ExpKeyType
) -> Type[BaseDSS]:
	return _determine_pqa_class(
		armored_key,
		expected_key_type,
		supported_algos=dict(
			DILITHIUM=Dilithium,
			FALCON=Falcon,
			FAST_SPHINCS=FastSphincs,
			SMALL_SPHINCS=SmallSphincs
		),
		pqa_type="DSS"
	)


def _determine_pqa_class(
		armored_key: str,
		expected_key_type: ExpKeyType,
		supported_algos: dict,
		pqa_type: Literal["KEM", "DSS"]
) -> Type[BaseKEM | BaseDSS]:
	header_pattern = r"^-----BEGIN (?P<hdr_name>[A-Z_]+) (?P<hdr_type>[A-Z_]+) KEY-----\n"
	footer_pattern = r"\n-----END (?P<ftr_name>[A-Z_]+) (?P<ftr_type>[A-Z_]+) KEY-----$"
	full_pattern = header_pattern + r"(?P<content>.+)" + footer_pattern

	full_match = re.match(full_pattern, armored_key, re.DOTALL)
	fm = DotMap(full_match.groupdict())

	if full_match is None or not fm["content"].strip():
		raise SystemExit("The armored key data is corrupted.\n")
	elif fm.hdr_name not in supported_algos.keys():
		raise SystemExit(f"Unsupported {pqa_type} algorithm in armored key header.\n")
	elif fm.hdr_type not in ["PUBLIC", "SECRET"]:
		raise SystemExit("Unsupported key type in armored key header.\n")
	elif fm.hdr_name != fm.ftr_name or fm.hdr_type != fm.ftr_type:
		raise SystemExit("The envelope of the armored key is corrupted.\n")
	elif fm.hdr_type != expected_key_type:
		raise SystemExit(
			f"Expected a {expected_key_type.lower()} key, but "
			f"received a {fm.hdr_key_type.lower()} key instead.\n"
		)
	return supported_algos[fm.hdr_name]
