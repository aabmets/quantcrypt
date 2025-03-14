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

from typer import Option, Argument
from typing import Annotated
from quantcrypt.internal import constants as const


__all__ = [
    "CompileAlgos",
    "KeygenAlgo",
    "Version",
    "DryRun",
    "Overwrite",
    "NonInteractive",
    "PubKeyFile",
    "SecKeyFile",
    "EncInFile",
    "EncOutFile",
    "DecInFile",
    "DecOutFile",
    "SignDataFile",
    "VerifyDataFile",
    "WriteSigFile",
    "ReadSigFile",
    "Identifier",
    "Directory",
    "WithOpt"
]


_algo_choices = ' | '.join(const.SupportedAlgos.armor_names())


KeygenAlgo = Annotated[str, Argument(
    show_default=False, case_sensitive=False, help=' '.join([
        "Name of the algorithm with which to generate the keypair (case insensitive).",
        f"Available choices: {_algo_choices}"
    ])
)]

CompileAlgos = Annotated[list[str], Argument(
    show_default=False, case_sensitive=False, help=' '.join([
        "Names of the algorithms which to compile, optional (case insensitive)." ,
        "If not provided, all algorithms will be compiled.",
        "Can accept multiple values separated by spaces.",
        f"Available choices: {_algo_choices}"
    ])
)]

WithOpt = Annotated[bool, Option(
    "--with-opt", "-o", show_default=False, help=' '.join([
        "Includes architecture-specific optimized variants to compilation targets.",
        "On x86_64 systems, this will add avx2 variants and on ARM systems, this will add aarch64 variants."
    ])
)]

Version = Annotated[bool, Option(
    '--version', '-v', show_default=False,
    help="Prints version number to the console and exits."
)]

DryRun = Annotated[bool, Option(
    "--dry-run", "-D", show_default=False,
    help="Skips actual file operations. Useful for testing purposes."
)]

Overwrite = Annotated[bool, Option(
    "--overwrite", "-W", show_default=False,
    help="Disables interactive confirmation prompt for overwriting files."
)]

NonInteractive = Annotated[bool, Option(
    "--non-interactive", "-N", show_default=False, help=' '.join([
        "Disables interactive prompts. If the program is going to overwrite",
        "files and the --overwrite option is not separately provided, the",
        "program will exit with an exit code of 1."
    ])
)]

PubKeyFile = Annotated[str, Option(
    '--pk-file', '-p', show_default=False, help=' '.join([
        "Either an absolute or a relative path to an armored PQA public key file.",
        "If the path is relative, it is evaluated from the Current Working Directory."
    ])
)]

SecKeyFile = Annotated[str, Option(
    '--sk-file', '-s', show_default=False, help=' '.join([
        "Either an absolute or a relative path to an armored PQA secret key file.",
        "If the path is relative, it is evaluated from the Current Working Directory."
    ])
)]

EncInFile = Annotated[str, Option(
    '--in-file', '-i', show_default=False, help=' '.join([
        "Path to the plaintext data file, which will be encrypted with the Krypton cipher.",
        "If the path is relative, it is evaluated from the Current Working Directory."
    ])
)]

EncOutFile = Annotated[str, Option(
    '--out-file', '-o', show_default=False, help=' '.join([
        "Path to the output file where the encrypted data will be written to, optional.",
        "Defaults to the Current Working Directory, using the data file name "
        f"with the {const.KryptonFileSuffix} suffix."
    ])
)]

DecInFile = Annotated[str, Option(
    '--in-file', '-i', show_default=False, help=' '.join([
        "Path to the ciphertext data file, which will be decrypted with the Krypton cipher.",
        "If the path is relative, it is evaluated from the Current Working Directory."
    ])
)]

DecOutFile = Annotated[str, Option(
    '--out-file', '-o', show_default=False, help=' '.join([
        "Path to the output file where the decrypted data will be written to, optional.",
        "Defaults to the Current Working Directory, using the original filename of the",
        "plaintext file that was stored into the ciphertext file."
    ])
)]

SignDataFile = Annotated[str, Option(
    '--in-file', '-i', show_default=False, help=' '.join([
        "Path to the data file, which will be signed by a DSS algorithm.",
        "The appropriate DSS algorithm is deduced from the contents of the armored key file.",
        "If the path is relative, it is evaluated from the Current Working Directory."
    ])
)]

VerifyDataFile = Annotated[str, Option(
    '--in-file', '-i', show_default=False, help=' '.join([
        "Path to the data file, which will be verified by a DSS algorithm.",
        "The appropriate DSS algorithm is deduced from the contents of the armored key file.",
        "If the path is relative, it is evaluated from the Current Working Directory."
    ])
)]

WriteSigFile = Annotated[str, Option(
    '--sig-file', '-S', show_default=False, help=' '.join([
        "Path to a file where the signature data will be written to, optional.",
        "Defaults to the Current Working Directory, using the data file name "
        f"with the {const.SignatureFileSuffix} suffix."
    ])
)]

ReadSigFile = Annotated[str, Option(
    '--sig-file', '-S', show_default=False, help=' '.join([
        "Path to a file where the signature data will be read from, optional.",
        "Defaults to the Current Working Directory, using the data file name "
        f"with the {const.SignatureFileSuffix} suffix."
    ])
)]

Identifier = Annotated[str, Option(
    "--id", "-i", show_default=False,
    help="Unique identifier to prepend to the names of the keyfiles, optional."
)]

Directory = Annotated[str, Option(
    "--dir", "-d", show_default=False, help=' '.join([
        "Directory where to save the generated keypair, optional.",
        "If the directory doesn't exist, it will be created with parents.",
        "If not provided, the keys are saved into the Current Working Directory."
    ])
)]
