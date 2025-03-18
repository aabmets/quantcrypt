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

import argparse
from typing import Any
from packaging import tags
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        first_tag = list(tags.sys_tags())[0]
        build_data["pure_python"] = False
        build_data["infer_tag"] = False
        build_data["tag"] = '-'.join([
            first_tag.interpreter,
            first_tag.abi,
            first_tag.platform
        ])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--compile", action="store_true", default=False)
    args = parser.parse_args()

    if args.compile:
        from quantcrypt.internal.compiler import Compiler
        Compiler.run(verbose=True)
