# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise the license page sync against small pages."""

import unittest

import license_page

LICENSE = "Copyright notice\n\n   Apache License\n   Version 2.0\n"
INTRO = "---\ntitle: License\n---\n\nIntro text.\n\n"
HEADING = "## Apache License 2.0\n\n```text\n"
OUTRO = "\nClosing text.\n"


def page(block):
    """Return a page whose license block holds `block`."""
    return INTRO + HEADING + block + "```\n" + OUTRO


class LicensePageTests(unittest.TestCase):
    def test_matching_page_is_unchanged(self):
        updated = license_page.with_license(page(LICENSE), LICENSE)
        self.assertEqual(updated, page(LICENSE))

    def test_stale_block_is_replaced_and_the_rest_kept(self):
        stale = page("   Apache License\n   Copyright 2025 Someone\n")
        self.assertEqual(license_page.with_license(stale, LICENSE), page(LICENSE))

    def test_license_without_final_newline_still_closes_the_fence(self):
        updated = license_page.with_license(page("old\n"), LICENSE.rstrip("\n"))
        self.assertEqual(updated, page(LICENSE))

    def test_missing_or_duplicate_block_fails(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            license_page.with_license(INTRO + OUTRO, LICENSE)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            license_page.with_license(page("a\n") + page("b\n"), LICENSE)

    def test_unclosed_block_fails(self):
        with self.assertRaisesRegex(ValueError, "no closing"):
            license_page.with_license(INTRO + HEADING + "old\n", LICENSE)


if __name__ == "__main__":
    unittest.main()
