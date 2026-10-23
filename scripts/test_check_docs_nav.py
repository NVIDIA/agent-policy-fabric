# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise the docs link check against the link forms GitHub and Fern accept."""

from pathlib import Path
import tempfile
import textwrap
import unittest

import check_docs_nav as nav


class LinkCheckTests(unittest.TestCase):
    """Check one page at a time in a small docs tree."""

    def setUp(self):
        """Create docs/ with an index, a target page, and a page under test."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.docs = Path(self.temp.name) / "docs"
        (self.docs / "about").mkdir(parents=True)
        (self.docs / "index.mdx").write_text("# Home\n")
        (self.docs / "about" / "architecture.mdx").write_text("# Architecture\n")

    def issues(self, body):
        """Return the link issues for about/page.mdx with the given body."""
        (self.docs / "about" / "page.mdx").write_text(textwrap.dedent(body))
        check = nav.NavCheck(self.docs)
        check.check_links()
        return check.issues

    def assertFlagged(self, body, *lines):
        """Assert that exactly the given lines of the page are flagged."""
        flagged = [int(issue.split(":")[1]) for issue in self.issues(body)]
        self.assertEqual(flagged, list(lines))

    def test_relative_mdx_links_pass(self):
        self.assertFlagged(
            """\
            [Architecture](architecture.mdx#trust-boundary)
            [Home](../index.mdx "Title")
            [Section](#same-page)
            [External](https://example.org/)
            """
        )

    def test_site_path_extensionless_and_outside_links_fail(self):
        issues = self.issues(
            """\
            [Architecture](/about/architecture)
            [Architecture](architecture)
            [Repository](../../README.md)
            [Folder](../about/)
            """
        )
        self.assertEqual(len(issues), 4)
        self.assertIn("is a site path", issues[0])
        self.assertIn("Add the .mdx extension", issues[1])
        self.assertIn("leaves docs/", issues[2])
        self.assertIn("is not a file", issues[3])

    def test_reference_definitions(self):
        self.assertFlagged(
            """\
            Read [Architecture][arch] and [Home][home].

            [arch]: /about/architecture
            [home]: ../index.mdx
            [^1]: A footnote, not a link: /about/architecture
            """,
            3,
        )

    def test_reference_definition_on_next_line(self):
        self.assertFlagged(
            """\
            [arch]:
              /about/architecture
            """,
            2,
        )

    def test_inline_destination_on_next_line(self):
        self.assertFlagged(
            """\
            Read [Architecture](
            /about/architecture) and [Home](
              ../index.mdx).
            """,
            2,
        )

    def test_jsx_props(self):
        self.assertFlagged(
            """\
            <Card title="A" href="architecture.mdx">
            <Card title="B" href = "/about/architecture">
            <Card title="C" href={"/about/architecture"}>
            <Card title="D" href={ 'architecture.mdx' }>
            <img src='../missing.svg' />
            """,
            2,
            3,
            5,
        )

    def test_angle_destinations(self):
        self.assertFlagged(
            """\
            [Architecture](<architecture.mdx>)
            [Example](<https://example.org/>)
            [Missing](<missing.mdx>)
            [arch]: <architecture.mdx>
            <Card href="<architecture.mdx>">
            """,
            3,
            5,
        )

    def test_longer_fence_contains_shorter_fence(self):
        self.assertFlagged(
            """\
            ````md
            ```
            [Example](/about/architecture)
            ```
            ````

            [Architecture](/about/architecture)
            """,
            7,
        )

    def test_fence_closes_only_on_matching_marker(self):
        self.assertFlagged(
            """\
            ~~~md
            ```
            [Example](/about/architecture)
            ~~~
            ```md
            ```text
            [Example](/about/architecture)
            ```
            [Architecture](/about/architecture)
            """,
            9,
        )

    def test_code_spans_are_ignored(self):
        self.assertFlagged(
            """\
            Write `[Example](/about/architecture)` or ``[`x`](/about/architecture)``.
            [Architecture](/about/architecture)
            """,
            2,
        )


if __name__ == "__main__":
    unittest.main()
