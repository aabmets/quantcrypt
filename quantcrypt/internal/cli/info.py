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
import site
from pathlib import Path
from dotmap import DotMap


__all__ = ["PackageInfo"]


class PackageInfo(DotMap):
    _PACKAGE_NAME = "quantcrypt"

    def __init__(self) -> None:
        super().__init__()

        for site_dir in site.getsitepackages():
            if "site-packages" not in site_dir:  # pragma: no cover
                continue

            for child in Path(site_dir).iterdir():
                is_self_pkg = child.name.startswith(self._PACKAGE_NAME)
                if not is_self_pkg or child.suffix != '.dist-info':
                    continue

                meta = child / 'METADATA'
                with meta.open("r") as file:
                    lines = file.readlines()
                self._set_fields(lines)

    def _set_fields(self, lines: list[str]) -> None:
        for line in lines:
            if line.startswith("\n"):
                break
            k, v = line.split(": ", maxsplit=1)
            if k in ["Name", "Version", "Summary"]:
                setattr(self, k, v.rstrip())
            elif k == "License-Expression":
                setattr(self, "License", v.rstrip())
            elif k == "Author-email":
                setattr(self, "Author", v.rstrip())
            elif v.startswith("Repository"):
                setattr(self, "Homepage", v.split(', ')[1].rstrip())
