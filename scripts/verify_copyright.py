#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Verify and fix SPDX copyright/license headers.

Enforces, on every matched source file, a two-line header:

    // SPDX-FileCopyrightText: Copyright (c) <year(s)> NVIDIA CORPORATION & AFFILIATES. All rights reserved.
    // SPDX-License-Identifier: Apache-2.0

`<year(s)>` is either a single year (e.g. `2026`) or a hyphenated range
(e.g. `2024-2026`). A file passes as long as the trailing year is >= the
year of that file's last git commit (uncommitted files use today's year).

Usage:
    verify_copyright.py --check [FILES...]   # exit 1 if anything is missing/stale
    verify_copyright.py --fix   [FILES...]   # rewrite headers in place
    (no FILES means: every git-tracked file with a known extension)
"""

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

HOLDER = "NVIDIA CORPORATION & AFFILIATES"

COMMENT_STYLES = {
    ".rs": "//",
    ".proto": "//",
    ".py": "#",
    ".sh": "#",
}

# Vendored third-party sources keep their upstream headers.
VENDORED_PREFIX = "contracts/third_party/"

YEAR_RE = r"(?:\d{4}-)?(?P<year>\d{4})"
COPYRIGHT_RE = re.compile(
    r"^\s*(?://|#)\s*SPDX-FileCopyrightText:\s*Copyright \(c\) "
    + YEAR_RE
    + r" "
    + re.escape(HOLDER)
    + r"\.\s*All rights reserved\.\s*$"
)
LICENSE_RE = re.compile(r"^\s*(?://|#)\s*SPDX-License-Identifier:\s*Apache-2\.0\s*$")
SHEBANG_RE = re.compile(r"^#!")


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


def is_vendored(path: Path, root: Path) -> bool:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return rel.as_posix().startswith(VENDORED_PREFIX)


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    files = []
    for line in out.stdout.splitlines():
        p = root / line
        if line.startswith(VENDORED_PREFIX):
            continue
        if p.suffix in COMMENT_STYLES and "/target/" not in line:
            files.append(p)
    return files


def commit_year(path: Path, root: Path) -> int:
    """Last commit year for `path`, or this year if untracked/uncommitted."""
    rel = str(path.relative_to(root)) if path.is_absolute() else str(path)
    out = subprocess.run(
        ["git", "-C", str(root), "log", "-1", "--format=%ad", "--date=format:%Y", "--", rel],
        capture_output=True,
        text=True,
    )
    year = out.stdout.strip()
    if year:
        return int(year)
    return datetime.date.today().year


def creation_year(path: Path, root: Path) -> int:
    """First commit year for `path`, falling back to `commit_year`."""
    rel = str(path.relative_to(root)) if path.is_absolute() else str(path)
    out = subprocess.run(
        ["git", "-C", str(root), "log", "--follow", "--format=%ad", "--date=format:%Y", "--", rel],
        capture_output=True,
        text=True,
    )
    years = out.stdout.split()
    if years:
        return int(years[-1])
    return commit_year(path, root)


def desired_year_field(path: Path, root: Path) -> str:
    first, last = creation_year(path, root), commit_year(path, root)
    return str(first) if first == last else f"{first}-{last}"


def build_header(prefix: str, year_field: str) -> list[str]:
    return [
        f"{prefix} SPDX-FileCopyrightText: Copyright (c) {year_field} {HOLDER}. All rights reserved.\n",
        f"{prefix} SPDX-License-Identifier: Apache-2.0\n",
    ]


def process(path: Path, root: Path, fix: bool) -> tuple[bool, str | None]:
    """Returns (needs_change, reason_if_any)."""
    prefix = COMMENT_STYLES[path.suffix]
    text = path.read_text()
    lines = text.splitlines(keepends=True)

    insert_at = 0
    if lines and SHEBANG_RE.match(lines[0]):
        insert_at = 1

    copyright_idx = None
    license_idx = None
    scan_end = min(len(lines), insert_at + 5)
    for i in range(insert_at, scan_end):
        if copyright_idx is None and COPYRIGHT_RE.match(lines[i]):
            copyright_idx = i
        if license_idx is None and LICENSE_RE.match(lines[i]):
            license_idx = i

    required_year = commit_year(path, root)
    reasons = []

    if copyright_idx is None:
        reasons.append("missing copyright line")
        stale = True
    else:
        match = COPYRIGHT_RE.match(lines[copyright_idx])
        trailing_year = int(match.group("year"))
        stale = trailing_year < required_year
        if stale:
            reasons.append(f"stale copyright year ({trailing_year} < {required_year})")

    if license_idx is None:
        reasons.append("missing license line")

    needs_change = bool(reasons)
    if not needs_change:
        return False, None

    if not fix:
        return True, "; ".join(reasons)

    # Rebuild: drop any existing copyright/license lines, then insert a fresh pair.
    body = [
        l
        for idx, l in enumerate(lines)
        if not (idx == copyright_idx or idx == license_idx)
    ]
    year_field = desired_year_field(path, root)
    header = build_header(prefix, year_field)
    new_lines = body[:insert_at] + header + body[insert_at:]
    path.write_text("".join(new_lines))
    return True, "; ".join(reasons)


def main() -> int:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--fix", action="store_true")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()

    root = repo_root()
    if args.files:
        paths = [
            p
            for p in (Path(f).resolve() for f in args.files if Path(f).suffix in COMMENT_STYLES)
            if not is_vendored(p, root)
        ]
    else:
        paths = tracked_files(root)

    changed = []
    for path in paths:
        if not path.is_file():
            continue
        needs_change, reason = process(path, root, fix=args.fix)
        if needs_change:
            changed.append((path, reason))

    if not changed:
        print("verify-copyright: all headers up to date")
        return 0

    verb = "fixed" if args.fix else "would need fixing"
    for path, reason in changed:
        rel = path.relative_to(root) if path.is_absolute() else path
        print(f"verify-copyright: {rel} — {reason} ({verb})")

    if args.fix:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
