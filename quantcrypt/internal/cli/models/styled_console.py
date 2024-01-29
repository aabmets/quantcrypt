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
from rich.prompt import Confirm
from rich.console import Console


class StyledConsole:
	@classmethod
	def _style_name(cls, message: str) -> str:
		sub = "[bold hot_pink3]QuantCrypt[/]"
		return message.replace("QuantCrypt", sub)

	@classmethod
	def _print(cls, message, color, end) -> None:
		console = Console(soft_wrap=True)
		if isinstance(color, str):
			console.print(f"[{color}]{message}[/]", end=end)
		else:
			console.print(f"{message}", end=end)

	@classmethod
	def print(cls, message: str, end='\n') -> None:
		message = cls._style_name(message)
		cls._print(message, color=None, end=end)

	@classmethod
	def print_success(cls, end='\n\n') -> None:
		cls._print(
			message=" :heavy_check_mark: Operation successful!",
			color="chartreuse3",
			end=end
		)

	@classmethod
	def print_cancelled(cls, end='\n\n') -> None:
		cls._print(
			message=" :warning: Operation cancelled.",
			color="gold3",
			end=end
		)

	@classmethod
	def raise_error(cls, message: str, end='\n\n') -> None:
		cls._print(
			message=":cross_mark:  QuantCrypt Error:",
			color="bold bright_red",
			end='\n'
		)
		cls._print(
			message=message,
			color=None,
			end=end
		)
		raise SystemExit(1)

	@classmethod
	def ask_continue(cls, exit_on_false: bool = False) -> bool:
		answer = Confirm.ask("Do you want to continue?")
		if exit_on_false is True and answer is False:
			StyledConsole.print_cancelled()
			raise SystemExit(0)
		return answer

	@classmethod
	def ask_overwrite_files(cls, exit_on_false: bool = False) -> bool:
		answer = Confirm.ask("Okay to overwrite existing files?")
		if exit_on_false is True and answer is False:
			StyledConsole.print_cancelled()
			raise SystemExit(0)
		return answer
