#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Keep the license text on the docs license page identical to LICENSE.

docs/resources/license.mdx shows the full license in the ```text block under
"## Apache License 2.0". The root LICENSE is the source of truth: `--check`
fails when the block differs from it, and a run without `--check` copies
LICENSE into the block.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

PAGE = Path("docs/resources/license.mdx")
BLOCK_START = "## Apache License 2.0\n\n```text\n"
FENCE = "```"


def block_span(page: str) -> tuple[int, int]:
    """Return the start and end offsets of the license text in the page."""
    start = page.find(BLOCK_START)
    if start < 0 or page.find(BLOCK_START, start + 1) >= 0:
        raise ValueError(f"expected exactly one {BLOCK_START!r} block")
    start += len(BLOCK_START)
    end = start
    for line in page[start:].splitlines(keepends=True):
        if line.rstrip("\n") == FENCE:
            return start, end
        end += len(line)
    raise ValueError("the license block has no closing ```")


def with_license(page: str, license_text: str) -> str:
    """Return the page with its license block replaced by `license_text`."""
    if not license_text.endswith("\n"):
        license_text += "\n"
    start, end = block_span(page)
    return page[:start] + license_text + page[end:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Copy LICENSE into the docs license page, or check that it matches."
    )
    parser.add_argument(
        "--check", action="store_true", help="fail if the page differs from LICENSE"
    )
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    page_path = args.repo_root / PAGE
    page = page_path.read_text(encoding="utf-8")
    license_text = (args.repo_root / "LICENSE").read_text(encoding="utf-8")
    try:
        updated = with_license(page, license_text)
    except ValueError as err:
        print(f"license page: {PAGE}: {err}", file=sys.stderr)
        return 1
    if updated == page:
        print(f"license page: {PAGE} matches LICENSE")
        return 0
    if args.check:
        diff = difflib.unified_diff(
            page.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=str(PAGE),
            tofile=f"{PAGE} (from LICENSE)",
            n=1,
        )
        sys.stderr.writelines(diff)
        print(
            f"license page: {PAGE} differs from LICENSE. "
            "Run `mise run license-page:update` and commit the result.",
            file=sys.stderr,
        )
        return 1
    page_path.write_text(updated, encoding="utf-8")
    print(f"license page: copied LICENSE into {PAGE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
