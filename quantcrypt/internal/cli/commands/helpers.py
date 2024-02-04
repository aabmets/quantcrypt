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
	BaseDSS, Dilithium, Falcon,
	FastSphincs, SmallSphincs
)
from .. import console


__all__ = [
	"resolve_optional_file",
	"resolve_directory",
	"process_paths",
	"determine_kem_class",
	"determine_dss_class"
]


@dataclass
class CommandPaths:
	key_file: Path
	in_file: Path
	out_file: Path
	sig_file: Path


ExpKeyType = Literal["PUBLIC", "SECRET"]


def resolve_optional_file(optional_file: str | None, from_file: Path, new_suffix: str) -> Path:
	if optional_file is None:
		return from_file.with_suffix(new_suffix)
	return utils.resolve_relpath(optional_file)


def resolve_directory(dir_arg: str | None) -> Path:
	target_dir = utils.resolve_relpath(dir_arg)
	if target_dir.is_file():
		console.raise_error(
			"The provided path is not a directory: "
			f"[italic tan]{target_dir}"
		)
	elif not target_dir.exists():
		target_dir.mkdir(parents=True)
	return target_dir


def process_paths(
		key_file: str, in_file: str, out_file: str,
		new_suffix: str, out_file_must_exist: bool = False
	) -> CommandPaths:
	_key_file = utils.resolve_relpath(key_file)
	_in_file = utils.resolve_relpath(in_file)
	_out_file = resolve_optional_file(
		optional_file=out_file,
		from_file=_in_file,
		new_suffix=new_suffix
	)
	files = [_key_file, _in_file]
	if out_file_must_exist:
		files.append(_out_file)

	for file in files:
		if not file.is_file():
			console.raise_error(
				f"File [italic sky_blue2]{file.name}[/] does not "
				f"exist in directory:\n[italic tan]{file.parent}"
			)
	return CommandPaths(
		key_file=_key_file,
		in_file=_in_file,
		out_file=_out_file,
		sig_file=_out_file
	)


def determine_kem_class(armored_key: str, exp_kt: ExpKeyType) -> Type[BaseKEM]:
	return _determine_pqa_class(
		armored_key, exp_kt,
		sup_algos=dict(
			KYBER=Kyber
		),
		pqa_type="KEM"
	)


def determine_dss_class(armored_key: str, exp_kt: ExpKeyType) -> Type[BaseDSS]:
	return _determine_pqa_class(
		armored_key, exp_kt,
		sup_algos=dict(
			DILITHIUM=Dilithium,
			FALCON=Falcon,
			FASTSPHINCS=FastSphincs,
			SMALLSPHINCS=SmallSphincs
		),
		pqa_type="DSS"
	)


def _determine_pqa_class(
		armored_key: str, exp_kt: ExpKeyType, sup_algos: dict, pqa_type: Literal["KEM", "DSS"]
	) -> Type[BaseKEM | BaseDSS]:
	header_pattern = r"^-----BEGIN (?P<hdr_name>[A-Z_]+) (?P<hdr_type>[A-Z_]+) KEY-----\n"
	footer_pattern = r"\n-----END (?P<ftr_name>[A-Z_]+) (?P<ftr_type>[A-Z_]+) KEY-----$"
	full_pattern = header_pattern + r"(?P<content>.+)" + footer_pattern

	full_match = re.match(full_pattern, armored_key, re.DOTALL)
	fm = DotMap(full_match.groupdict()) if full_match else None

	if fm is None or not fm["content"].strip():
		console.raise_error("The armored key data is corrupted.")
	elif fm.hdr_name not in sup_algos.keys():
		console.raise_error(f"Unsupported {pqa_type} algorithm in armored key header.")
	elif fm.hdr_type not in ["PUBLIC", "SECRET"]:
		console.raise_error("Unsupported key type in armored key header.")
	elif fm.hdr_name != fm.ftr_name or fm.hdr_type != fm.ftr_type:
		console.raise_error("The envelope of the armored key is corrupted.")
	elif fm.hdr_type != exp_kt:
		console.raise_error(
			f"Expected a {exp_kt.lower()} key, but received "
			f"a {fm.hdr_type.lower()} key instead."
		)
	if fm is not None:
		return sup_algos[fm.hdr_name]

	console.raise_error(  # pragma: no cover
		"Unspecified error with the armored keyfile."
	)
