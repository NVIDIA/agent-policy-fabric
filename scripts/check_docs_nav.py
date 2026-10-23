#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "PyYAML==6.0.2",
# ]
# ///

"""Check that the published docs navigation mirrors the docs folder structure,
and that links between pages work both on GitHub and in Fern.

Fern does not build page URLs from file paths. It uses, in order, the page's
frontmatter `slug`, the nav entry's `slug`, or the nav label, and it splits
camel case in labels, so "TypeScript" becomes `type-script`. Pages in a
`folder:` section use their file names. A URL can therefore drift away from
where its file lives without any link breaking.

Pages link to each other's .mdx files with relative paths. GitHub follows the
file path, and Fern rewrites a link to an .mdx file into that page's URL when
it builds the site. A site path such as `/about/architecture` works only in
Fern, and a relative path without `.mdx` is not rewritten.

This check fails when:

- a page's version-relative URL differs from its file path under docs/,
  omitting `.mdx` and a trailing `/index`;
- a nav page's sidebar name, its `sidebar-title` or else its `title`, differs
  from its nav label. Fern shows the sidebar name but builds the URL from the
  label, so the two must agree;
- a docs page is not reachable from the navigation;
- a redirect for this docs version points to a URL that does not exist, or its
  source is still a live page; or
- a docs page links to a site path, or to a relative path that is not a file
  under docs/.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# PyYAML is imported where it is used, so the link check and its tests run
# without it.

# Files under docs/ that are intentionally not published as pages.
UNPUBLISHED = {"CONTRIBUTING.mdx"}

# A Markdown link destination: `<...>`, or a run without spaces whose
# parentheses are escaped or balanced one level deep. Group 1 is the angle form
# without its brackets, group 2 the bare form.
_DEST = (
    r"(?:<([^<>\n]*)>"
    r"|((?:[^\s()<\\]|\\.|\((?:[^\s()\\]|\\.)*\))"
    r"(?:[^\s()\\]|\\.|\((?:[^\s()\\]|\\.)*\))*))"
)
# `[text](dest)` and `![alt](dest)`, with the destination on the same line or
# the next one.
INLINE_LINK = re.compile(r"\]\([ \t]*\n?[ \t]*" + _DEST)
# `[label]: dest`, a reference definition. GFM footnotes, `[^1]:`, are not links.
REFERENCE_DEFINITION = re.compile(
    r"^[ \t]*\[(?!\^)[^\]\n]+\]:[ \t]*\n?[ \t]*" + _DEST, re.M
)
# JSX `href` and `src` props, as a string or a string in braces. Angle brackets
# in a prop are literal, so this keeps them.
JSX_LINK = re.compile(r"""\b(?:href|src)\s*=\s*(?:\{\s*)?(?:"([^"\n]*)"|'([^'\n]*)')""")
FENCE_OPEN = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
# A code span: a backtick run closed by a run of the same length, within one
# paragraph.
CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)((?:(?!\n[ \t]*\n).)+?)(?<!`)\1(?!`)", re.S)
# URL schemes, protocol-relative URLs, and same-page anchors.
NOT_A_PAGE_LINK = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//|#)", re.I)


def fern_slug(label: str) -> str:
    """Slugify a nav label the way Fern does, including camel-case splits."""
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", label)
    return re.sub(r"[^a-z0-9]+", "-", split.lower()).strip("-")


def path_url(rel_path: str) -> str:
    """Return the URL that a docs file path implies."""
    url = "/" + re.sub(r"\.mdx$", "", rel_path)
    return re.sub(r"/index$", "", url)


def frontmatter(path: Path) -> dict:
    import yaml

    match = re.match(r"---\n(.*?)\n---", path.read_text(encoding="utf-8"), re.S)
    if not match:
        return {}
    return yaml.safe_load(match.group(1)) or {}


def mask_code(text: str) -> str:
    """Blank out fenced code blocks and code spans, keeping every line break.

    A fence closes only on a line of the same marker, at least as long as the
    opening one, with nothing after it, so a shorter or different fence inside
    a code block stays part of the block.
    """
    lines = text.split("\n")
    fence = None  # The open fence's marker character and length.
    for i, line in enumerate(lines):
        if fence:
            char, length = fence
            if re.fullmatch(rf"[ \t]*{re.escape(char)}{{{length},}}[ \t]*", line):
                fence = None
            lines[i] = ""
            continue
        match = FENCE_OPEN.match(line)
        # A backtick fence's info string cannot contain a backtick.
        if match and not (match[1][0] == "`" and "`" in match[2]):
            fence = (match[1][0], len(match[1]))
            lines[i] = ""
    return CODE_SPAN.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), "\n".join(lines))


def page_links(text: str) -> list[tuple[int, str]]:
    """Return the line and destination of each link on a page, outside code."""
    text = mask_code(text)
    links = []
    for pattern in (INLINE_LINK, REFERENCE_DEFINITION, JSX_LINK):
        for match in pattern.finditer(text):
            group = 1 if match[1] is not None else 2
            target = match[group]
            if pattern is not JSX_LINK:
                target = re.sub(r"\\(.)", r"\1", target)
            if target:
                links.append((text.count("\n", 0, match.start(group)) + 1, target))
    return sorted(links)


@dataclass
class NavCheck:
    docs_root: Path
    urls: dict[str, str] = field(default_factory=dict)  # URL -> docs-relative path
    reachable: set[str] = field(default_factory=set)
    issues: list[str] = field(default_factory=list)

    def page_url(self, rel_path: str, default_url: str) -> str:
        slug = frontmatter(self.docs_root / rel_path).get("slug")
        return "/" + str(slug).strip("/") if slug else default_url

    def record(self, rel_path: str, url: str, how: str) -> None:
        self.reachable.add(rel_path)
        if url in self.urls and self.urls[url] != rel_path:
            self.issues.append(
                f"{rel_path}: URL {url} is also used by {self.urls[url]}"
            )
        self.urls[url] = rel_path
        expected = path_url(rel_path)
        if url != expected:
            self.issues.append(
                f"{rel_path}: URL {url} ({how}) does not match its file path "
                f"{expected}. Rename the file, change the nav label, or set a "
                "relative slug in docs/index.yml. For folder-discovered pages, "
                f'use frontmatter slug: "{expected.lstrip("/")}".'
            )

    def walk(self, items: list, prefix: str) -> None:
        for item in items or []:
            if "section" in item:
                url = prefix + "/" + item.get("slug", fern_slug(item["section"]))
                if item.get("skip-slug"):
                    url = prefix
                if "path" in item:
                    rel = item["path"]
                    self.record(rel, self.page_url(rel, url), "section page")
                self.walk(item.get("contents", []), url)
            elif "page" in item:
                rel, label = item["path"], item["page"]
                if not (self.docs_root / rel).exists():
                    self.issues.append(
                        f"docs/index.yml: nav page {label!r} points to missing {rel}"
                    )
                    continue
                if item.get("skip-slug"):
                    default, how = prefix, "skip-slug"
                elif str(item.get("slug")).strip("/") == "" and "slug" in item:
                    # `slug: /` serves the page at the root of its section or site.
                    default, how = prefix, "nav slug"
                elif "slug" in item:
                    default, how = prefix + "/" + item["slug"], "nav slug"
                else:
                    default, how = (
                        prefix + "/" + fern_slug(label),
                        f"nav label {label!r}",
                    )
                meta = frontmatter(self.docs_root / rel)
                how = "frontmatter slug" if meta.get("slug") else how
                self.record(rel, self.page_url(rel, default), how)
                shown_key = "sidebar-title" if "sidebar-title" in meta else "title"
                shown = meta.get(shown_key)
                if shown != label:
                    self.issues.append(
                        f"{rel}: {shown_key} {shown!r} does not match nav label {label!r}"
                    )
            elif "folder" in item:
                folder = item["folder"].strip("./").rstrip("/")
                url = (
                    prefix
                    + "/"
                    + item.get("slug", fern_slug(item.get("title", folder)))
                )
                if item.get("skip-slug"):
                    url = prefix
                for page in sorted((self.docs_root / folder).rglob("*.mdx")):
                    rel = page.relative_to(self.docs_root).as_posix()
                    stem = (
                        page.relative_to(self.docs_root / folder)
                        .with_suffix("")
                        .as_posix()
                    )
                    default = re.sub(r"/index$", "", url + "/" + stem)
                    how = (
                        "frontmatter slug"
                        if frontmatter(page).get("slug")
                        else "folder file name"
                    )
                    self.record(rel, self.page_url(rel, default), how)

    def check_orphans(self) -> None:
        for page in sorted(self.docs_root.rglob("*.mdx")):
            rel = page.relative_to(self.docs_root).as_posix()
            if rel in UNPUBLISHED or rel in self.reachable or rel.startswith("_"):
                continue
            self.issues.append(f"{rel}: not reachable from docs/index.yml")

    def check_links(self) -> None:
        docs_root = self.docs_root.resolve()
        for page in sorted(self.docs_root.rglob("*.mdx")):
            rel = page.relative_to(self.docs_root).as_posix()
            for lineno, target in page_links(page.read_text(encoding="utf-8")):
                if NOT_A_PAGE_LINK.match(target):
                    continue
                path = re.split(r"[#?]", target, maxsplit=1)[0]
                where = f"{rel}:{lineno}: link {target}"
                if path.startswith("/"):
                    self.issues.append(
                        f"{where} is a site path, which GitHub cannot follow. "
                        "Link to the page's .mdx file with a relative path."
                    )
                    continue
                resolved = (page.parent / path).resolve()
                if docs_root not in resolved.parents:
                    self.issues.append(
                        f"{where} leaves docs/, which Fern does not publish. "
                        "Name the file in code formatting instead."
                    )
                elif not resolved.is_file():
                    hint = (
                        " Add the .mdx extension."
                        if resolved.with_name(resolved.name + ".mdx").is_file()
                        else ""
                    )
                    self.issues.append(f"{where} is not a file.{hint}")

    def check_redirects(self, redirects: list, prefix: str) -> None:
        live = set(self.urls) | {""}
        for redirect in redirects or []:
            source, dest = redirect.get("source", ""), redirect.get("destination", "")
            if dest.startswith(prefix + "/") or dest == prefix:
                target = dest[len(prefix) :].split("#", 1)[0].rstrip("/")
                if ":" not in target and target not in live:
                    self.issues.append(
                        f"fern/docs.yml: redirect {source} -> {dest}: destination does not exist"
                    )
            if source.startswith(prefix + "/") and ":" not in source:
                origin = source[len(prefix) :].rstrip("/")
                if origin in live:
                    self.issues.append(
                        f"fern/docs.yml: redirect source {source} is still a live page"
                    )


def redirect_prefix(fern_config: dict, nav_file: Path, config_dir: Path) -> str | None:
    """Return the URL prefix, such as /agent-policy-fabric/dev, for the checked version."""
    instances = fern_config.get("instances") or []
    url = instances[0].get("url", "") if instances else ""
    base = "/" + url.split("/", 1)[1].strip("/") if "/" in url else ""
    for version in fern_config.get("versions") or []:
        if (config_dir / version.get("path", "")).resolve() == nav_file.resolve():
            return f"{base}/{version['slug']}".replace("//", "/")
    return None


def run(repo_root: Path) -> list[str]:
    import yaml

    docs_root = repo_root / "docs"
    nav_file = docs_root / "index.yml"
    nav = yaml.safe_load(nav_file.read_text(encoding="utf-8"))
    check = NavCheck(docs_root)
    landing = (nav.get("landing-page") or {}).get("path")
    if landing:
        check.reachable.add(landing)
    check.walk(nav.get("navigation", []), "")
    check.check_orphans()
    check.check_links()
    fern_file = repo_root / "fern" / "docs.yml"
    if fern_file.exists():
        fern_config = yaml.safe_load(fern_file.read_text(encoding="utf-8"))
        prefix = redirect_prefix(fern_config, nav_file, fern_file.parent)
        if prefix:
            check.check_redirects(fern_config.get("redirects"), prefix)
    return check.issues


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that the published docs navigation mirrors the docs "
        "folder structure and that page links point to .mdx files."
    )
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    issues = run(args.repo_root)
    for issue in issues:
        print(f"docs nav: {issue}", file=sys.stderr)
    if issues:
        print(f"docs nav: {len(issues)} problem(s) found", file=sys.stderr)
        return 1
    print(
        "docs nav: every page URL matches its file path and every link points to a file"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
