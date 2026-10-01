# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise completeness and failure cases for distribution notices."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import third_party_licenses as notices


class NoticeTests(unittest.TestCase):
    """Use small source packages so checks cannot silently rely on Cargo caches."""

    def setUp(self):
        """Create a package with its own copyright and complete notice source."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "LICENSE-MIT").write_text(
            "Copyright (c) 2026 Example Authors\nPermission notice.\n"
        )
        self.package = dict(
            name="example",
            version="1.0.0",
            source="registry+https://github.com/rust-lang/crates.io-index",
            license="MIT",
            manifest_path=str(self.root / "Cargo.toml"),
            authors=[],
        )
        self.selections = json.loads(
            (notices.ROOT / "licenses/selections.json").read_text()
        )

    def render(self, packages=None, metadata=None, supplements=None):
        """Generate a lock fixture independently of the metadata being tested."""
        packages = packages if packages is not None else [self.package]
        lock = "\n".join(
            "[[package]]\n"
            + "\n".join(
                f"{key} = {json.dumps(p[key])}" for key in ("name", "version", "source")
            )
            for p in packages
        ).encode()
        return notices.render(
            metadata or {"packages": packages}, lock, self.selections, supplements or {}
        )

    def test_missing_locked_dependency_fails(self):
        """A filtered Cargo graph must not produce a partial product notice."""
        with self.assertRaisesRegex(ValueError, "metadata/lockfile mismatch"):
            self.render(metadata={"packages": []})

    def test_unknown_license_does_not_guess(self):
        """A newly introduced expression requires an explicit reviewed selection."""
        self.package["license"] = "MIT AND GPL-3.0-only"
        with self.assertRaisesRegex(ValueError, "review the new license expression"):
            self.render()

    def test_r_efi_rejects_lgpl_selection(self):
        """Changing the selection map cannot silently elect LGPL for r-efi."""
        self.package["name"] = "r-efi"
        self.package["license"] = "MIT OR Apache-2.0 OR LGPL-2.1-or-later"
        self.selections[self.package["license"]] = "LGPL-2.1-or-later"
        with self.assertRaisesRegex(ValueError, "r-efi must use"):
            self.render()

    def test_and_terms_versions_and_nested_notices_survive(self):
        """Keep both AND grants, distinct versions, and bundled-code attribution."""
        self.package["license"] = "MIT AND BSD-3-Clause"
        bundled = self.root / "vendor"
        bundled.mkdir()
        (bundled / "NOTICE").write_text("Copyright (c) 2025 Bundled Authors\n")
        second = dict(self.package, version="2.0.0")
        result = self.render(packages=[self.package, second])
        self.assertEqual(result.count("COMPONENT: example "), 2)
        self.assertIn("Selected license: MIT AND BSD-3-Clause", result)
        self.assertIn("Copyright (c) 2025 Bundled Authors", result)
        self.assertIn("vendor/NOTICE", result)
        self.assertNotIn(str(self.root), result)

    def test_missing_attribution_fails(self):
        """Generic permission text cannot substitute for component attribution."""
        (self.root / "LICENSE-MIT").write_text(
            "Permission notice without attribution.\n"
        )
        with self.assertRaisesRegex(ValueError, "no upstream copyright or attribution"):
            self.render()

    def test_changed_supplement_fails(self):
        """A pinned upstream license cannot change without updating its evidence."""
        target = self.root / "licenses/upstream"
        target.mkdir(parents=True)
        (target / "LICENSE").write_text("Unexpected license text")
        extra = {
            ("example", "1.0.0"): {
                "files": [
                    {
                        "filename": "LICENSE",
                        "sha256": "0" * 64,
                        "upstream_url": "https://example.invalid/LICENSE",
                    }
                ]
            }
        }
        with (
            patch.object(notices, "ROOT", self.root),
            self.assertRaisesRegex(ValueError, "checksum changed"),
        ):
            self.render(supplements=extra)

    def test_zlib_parenthetical_notice_is_a_copyright_statement(self):
        """A zlib-style `(C) YEAR holder` line is the copyright statement."""
        self.assertEqual(
            notices.copyright_lines("(C) 2024 Copyright\n"),
            {"(C) 2024 Copyright"},
        )

    def test_template_copyright_is_not_attribution(self):
        """Do not publish placeholders as if they identified a rights holder."""
        self.assertFalse(
            notices.copyright_lines(
                "Copyright (c) <year> <copyright holders>\nCopyright [yyyy] [name of copyright owner]\n2. Grant of Copyright License."
            )
        )

    def test_libm_source_notices_survive_root_copyright(self):
        """Root attribution must not hide grants for bundled math implementations."""
        self.package.update(name="libm", version="0.2.16")
        packages = json.loads(
            (notices.ROOT / "licenses/upstream/provenance.json").read_text()
        )["packages"]
        libm = next(p for p in packages if p["name"] == "libm")
        result = self.render(supplements={("libm", "0.2.16"): libm})
        self.assertIn("Copyright (c) 2021-2022 Alexei Sibidanov.", result)
        self.assertIn("Copyright (c) 2005 David Schultz <das@FreeBSD.ORG>", result)
        self.assertIn("2. Redistributions in binary form must reproduce", result)
        self.assertIn("Copyright (C) 1993 by Sun Microsystems, Inc.", result)
        self.assertIn("Permission to use, copy, modify, and distribute this", result)

    def test_version_bump_cannot_drop_source_supplement(self):
        """A dependency update must refresh previously required bundled notices."""
        self.package["version"] = "2.0.0"
        with self.assertRaisesRegex(ValueError, "review source supplements"):
            self.render(supplements={("example", "1.0.0"): {"files": []}})


if __name__ == "__main__":
    unittest.main()
