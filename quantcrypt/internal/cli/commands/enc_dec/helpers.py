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
from quantcrypt.internal.pqa.kem import BaseKEM, Kyber


__all__ = [
	"CommandPaths",
	"process_paths",
	"determine_kem_class"
]


@dataclass
class CommandPaths:
	key_file: Path
	data_file: Path
	out_file: Path


def process_paths(key_file: str, data_file: str, out_file: str) -> CommandPaths:
	_key_file = (
		Path.cwd() / key_file if
		utils.is_path_relative(key_file)
		else Path(key_file)
	)
	_data_file = (
		Path.cwd() / data_file if
		utils.is_path_relative(data_file)
		else Path(data_file)
	)
	if out_file is None:
		_out_file = _data_file.with_suffix(".kptn")
	else:
		_out_file = Path(out_file)
		if utils.is_path_relative(out_file):
			_out_file = Path.cwd() / out_file

	return CommandPaths(
		key_file=_key_file,
		data_file=_data_file,
		out_file=_out_file
	)


def determine_kem_class(armored_key: str, expected_key_type: Literal["PUBLIC", "SECRET"]) -> Type[BaseKEM]:
	supported_kem_algos = dict(KYBER=Kyber)

	header_pattern = r"^-----BEGIN (?P<hdr_name>[A-Z_]+) (?P<hdr_type>[A-Z_]+) KEY-----\n"
	footer_pattern = r"\n-----END (?P<ftr_name>[A-Z_]+) (?P<ftr_type>[A-Z_]+) KEY-----$"
	full_pattern = header_pattern + r"(?P<content>.+)" + footer_pattern

	full_match = re.match(full_pattern, armored_key, re.DOTALL)
	fm = DotMap(full_match.groupdict())

	if full_match is None or not fm["content"].strip():
		raise SystemExit("The armored key data is corrupted.\n")
	elif fm.hdr_name not in supported_kem_algos.keys():
		raise SystemExit("Unsupported KEM algorithm in armored key header.\n")
	elif fm.hdr_type not in ["PUBLIC", "SECRET"]:
		raise SystemExit("Unsupported key type in armored key header.\n")
	elif fm.hdr_name != fm.ftr_name or fm.hdr_type != fm.ftr_type:
		raise SystemExit("The envelope of the armored key is corrupted.\n")
	elif fm.hdr_type != expected_key_type:
		raise SystemExit(
			f"Expected a {expected_key_type.lower()} key, but "
			f"received a {fm.hdr_key_type.lower()} key instead.\n"
		)
	return supported_kem_algos[fm.hdr_name]
