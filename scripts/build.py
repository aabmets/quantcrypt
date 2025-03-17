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

# 1) This script is first called by cibuildwheel to compile PQA binaries.
try:
    from quantcrypt.internal.compiler import Compiler
    Compiler.run(verbose=True)
except ImportError:
    Compiler = None


# 2) Then it is called by hatchling to package the wheel.
# We need to fix the wheel tag and set pure_python false, because hatchling
# cannot obtain tag info from compilation processes that are external to itself.
try:
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
except ImportError:
    pass
