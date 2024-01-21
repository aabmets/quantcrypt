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
from quantcrypt.cipher import KryptonKEM
from . import helpers


encrypt_app = Typer(
	name="encrypt", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored KEM public key to encrypt a file with the Krypton cipher."
)
decrypt_app = Typer(
	name="decrypt", invoke_without_command=True, no_args_is_help=True, help=""
	"Uses an ASCII armored KEM secret key to decrypt a file with the Krypton cipher."
)


PKFileAtd = Annotated[str, Option(
	'--key-file', '-k', show_default=False, help=""
	"Either an absolute or a relative path to the armored PQA public key file, "
	"which will be encapsulated to produce the secret key for the Krypton cipher. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
SK_FileAtd = Annotated[str, Option(
	'--key-file', '-k', show_default=False, help=""
	"Either an absolute or a relative path to the armored PQA secret key file, "
	"which will be decapsulated to produce the secret key for the Krypton cipher. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
PTFileAtd = Annotated[str, Option(
	'--data-file', '-d', show_default=False, help=""
	"Path to the plaintext data file, which will be encrypted with the Krypton cipher. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
CTFileAtd = Annotated[str, Option(
	'--data-file', '-d', show_default=False, help=""
	"Path to the ciphertext data file, which will be decrypted with the Krypton cipher. "
	"If the path is relative, it is evaluated from the Current Working Directory."
)]
CTOutFileAtd = Annotated[str, Option(
	'--out-file', '-o', show_default=False, help=""
	"Path to the output file where the encrypted data will be written to, optional. "
	"Defaults to the Current Working Directory, using the data file name with the .kptn suffix."
)]
PTOutFileAtd = Annotated[str, Option(
	'--out-file', '-o', show_default=False, help=""
	"Path to the output file where the decrypted data will be written to, optional. "
	"Defaults to the Current Working Directory, using the original filename of the data file "
	"that was stored into the ciphertext file."
)]


@encrypt_app.callback()
def command_encrypt(key_file: PKFileAtd, data_file: PTFileAtd, out_file: CTOutFileAtd = None) -> None:
	paths = helpers.process_paths(key_file, data_file, out_file, '.kptn')

	with paths.key_file.open('r') as file:
		armored_key = file.read()

	kem_class = helpers.determine_kem_class(
		armored_key, "PUBLIC"
	)
	krypton = KryptonKEM(kem_class)
	krypton.encrypt(
		public_key=armored_key,
		data_file=paths.data_file,
		output_file=paths.target_file
	)
	print("File encrypted successfully!")


@decrypt_app.callback()
def command_decrypt(key_file: SK_FileAtd, data_file: CTFileAtd, out_file: PTOutFileAtd = None) -> None:
	paths = helpers.process_paths(key_file, data_file, out_file, '.kptn')

	with paths.key_file.open('r') as file:
		armored_key = file.read()

	kem_class = helpers.determine_kem_class(
		armored_key, "SECRET"
	)
	krypton = KryptonKEM(kem_class)
	krypton.decrypt_to_file(
		secret_key=armored_key,
		encrypted_file=paths.data_file,
		output_file=paths.target_file
	)
	print("File decrypted successfully!")
