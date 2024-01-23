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
from typer import Typer, Option
from quantcrypt.errors import QuantCryptError
from . import helpers


sign_app = Typer(
	name="sign", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored DSS secret key to generate a signature for a file."
)
verify_app = Typer(
	name="verify", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored DSS public key to verify the signature of a file."
)


PKFileAtd = Annotated[str, Option(
	'--key-file', '-k', show_default=False, help=""
	"Either an absolute or a relative path to an armored DSS public key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
SKFileAtd = Annotated[str, Option(
	'--key-file', '-k', show_default=False, help=""
	"Either an absolute or a relative path to an armored DSS secret key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
SignDataFileAtd = Annotated[str, Option(
	'--data-file', '-d', show_default=False, help=""
	"Path to the data file, which will be signed by a DSS algorithm. "
	"The appropriate DSS algorithm is deduced from the contents of the armored key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
VerifyDataFileAtd = Annotated[str, Option(
	'--data-file', '-d', show_default=False, help=""
	"Path to the data file, which will be verified by a DSS algorithm. "
	"The appropriate DSS algorithm is deduced from the contents of the armored key file. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
WriteSigFileAtd = Annotated[str, Option(
	'--sig-file', '-s', show_default=False, help=""
	"Path to a file where the signature data will be written to, optional. "
	"Defaults to the Current Working Directory, using the data file name with the .sig suffix."
)]
ReadSigFileAtd = Annotated[str, Option(
	'--sig-file', '-s', show_default=False, help=""
	"Path to a file where the signature data will be read from, optional. "
	"Defaults to the Current Working Directory, using the data file name with the .sig suffix."
)]


@sign_app.callback()
def command_sign(key_file: SKFileAtd, data_file: SignDataFileAtd, sig_file: WriteSigFileAtd = None) -> None:
	paths = helpers.process_paths(key_file, data_file, sig_file, ".sig")

	with paths.key_file.open('r') as file:
		armored_key = file.read()

	dss_class = helpers.determine_dss_class(
		armored_key, "SECRET"
	)
	dss = dss_class()
	try:
		signed_file = dss.sign_file(armored_key, paths.data_file)

		with paths.target_file.open('wb') as file:
			file.write(signed_file.signature)

		print("File signed successfully!")
	except QuantCryptError:
		print("Failed to sign file!")


@verify_app.callback()
def command_verify(key_file: PKFileAtd, data_file: VerifyDataFileAtd, sig_file: ReadSigFileAtd = None) -> None:
	paths = helpers.process_paths(key_file, data_file, sig_file, ".sig")

	with paths.key_file.open('r') as file:
		armored_key = file.read()

	with paths.target_file.open('rb') as file:
		signature = file.read()

	dss_class = helpers.determine_dss_class(
		armored_key, "PUBLIC"
	)
	dss = dss_class()
	try:
		dss.verify_file(armored_key, paths.data_file, signature)
		print("Signature verified successfully!")
	except QuantCryptError:
		print("Failed to verify signature!")
