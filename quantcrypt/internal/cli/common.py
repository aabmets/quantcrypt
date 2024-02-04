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
from typing import Annotated
from typer import Option


__all__ = [
	"DryRunAtd",
	"OverwriteAtd",
	"NonInteractiveAtd",
	"PubKeyFileAtd",
	"SecKeyFileAtd"
]


DryRunAtd = Annotated[bool, Option(
	"--dry-run", "-D", show_default=False, help=""
	"Skips actual file operations. Useful for testing purposes."
)]

OverwriteAtd = Annotated[bool, Option(
	"--overwrite", "-W", show_default=False, help=""
	"Disables interactive confirmation prompt for overwriting files."
)]

NonInteractiveAtd = Annotated[bool, Option(
	"--non-interactive", "-N", show_default=False, help=""
	"Disables interactive prompts. If the program is going to overwrite "
	"files and the --overwrite option is not separately provided, the "
	"program will exit with an exit code of 1."
)]

PubKeyFileAtd = Annotated[str, Option(
	'--pk-file', '-p', show_default=False, help=""
	"Either an absolute or a relative path to an armored PQA public key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]

SecKeyFileAtd = Annotated[str, Option(
	'--sk-file', '-s', show_default=False, help=""
	"Either an absolute or a relative path to an armored PQA secret key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
