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
from typing import Any
from rich.prompt import Confirm
from rich.console import Console
from rich.pretty import pprint


__all__ = [
	"pretty_print",
	"styled_print",
	"print_success",
	"print_cancelled",
	"raise_error",
	"ask_continue",
	"ask_overwrite_files",
	"notify_dry_run"
]


def _with_styled_name(message: str) -> str:
	sub = "[bold hot_pink3]QuantCrypt[/]"
	return message.replace("QuantCrypt", sub)


def _custom_print(message: str, color: str | None, end: str) -> None:
	console = Console(soft_wrap=True)
	if isinstance(color, str):
		message = f"[{color}]{message}[/]"
	console.print(message, end=end)


def pretty_print(message: Any) -> None:
	pprint(message, expand_all=True)


def styled_print(message: str, end='\n') -> None:
	msg = _with_styled_name(message)
	_custom_print(msg, color=None, end=end)


def print_success(end='\n\n') -> None:
	msg = " :heavy_check_mark: - Operation successful!"
	_custom_print(msg, color="chartreuse3", end=end)


def print_cancelled(end='\n\n') -> None:
	msg = " :warning: - Operation cancelled."
	_custom_print(msg, color="gold3", end=end)


def raise_error(reason: str, end='\n\n') -> None:
	msg = ":cross_mark:  - QuantCrypt Error:"
	_custom_print(msg, color="bold bright_red", end='\n')
	_custom_print(reason, color=None, end=end)
	raise SystemExit(1)


def ask_continue(exit_on_false: bool = False) -> bool:
	answer = Confirm.ask("Do you want to continue?")
	if exit_on_false is True and answer is False:
		print_cancelled()
		raise SystemExit(0)
	return answer


def ask_overwrite_files(non_interactive: bool, overwrite: bool, exit_on_false: bool) -> bool:
	if non_interactive and not overwrite:
		raise_error(
			"Must explicitly enable file overwriting with "
			"the [bold turquoise2]--overwrite[/] option in "
			"non-interactive mode."
		)
	elif not overwrite:
		answer = Confirm.ask("Okay to overwrite existing files?")
		if exit_on_false is True and answer is False:
			print_cancelled()
			raise SystemExit(0)
		return answer


def notify_dry_run(dry_run: bool, end='\n') -> None:
	if dry_run:
		emojis = ":exclamation:" * 3
		msg = f"{emojis} DRY RUN MODE {emojis}"
		_custom_print(msg, color="bold dark_orange", end=end)
