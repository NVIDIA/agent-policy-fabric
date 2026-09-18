// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Persistent monotonic-counter store; rejects bundles whose counter does not increase (anti-rollback).
//!
//! The [`CounterStore`] type alias defaults to the file-based backend.
//! For remote/hosted deployments, swap in a backend that persists to a
//! shared store (Redis, etcd, database) by implementing the same interface.
//!
//! The store records the highest accepted counter and the digest of the
//! verified payload accepted at that counter — the signed document's
//! content, not its signature envelope, so re-signing identical content
//! does not change it. A candidate is accepted when its counter is strictly
//! newer, or when it is the same counter carrying the same content — so a
//! restart can reload the bundle it was already serving — and rejected when
//! it is older or when it presents different content at an already-accepted
//! counter.
//!
//! Failure posture: if the backing store is missing the high-water mark is
//! 0 (fresh install). If it exists but is corrupt, loading fails — the
//! operator must intervene rather than risk silent rollback.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Type alias so callers don't couple to the concrete backend.
pub type CounterStore = FileCounterStore;

/// File-backed monotonic counter with atomic write-temp-then-rename.
///
/// The counter file holds only the decimal high-water mark, one line, so
/// external tooling can read it without parsing anything else. The payload
/// digest accepted at that counter lives in a sibling `<counter>.digest`
/// file as `<counter> <sha256-hex>`; the counter it names
/// must match the counter file for the digest to be trusted, so a crash
/// between the two writes degrades to "digest unknown" rather than to a
/// spurious rejection or a wrong binding.
///
/// Suitable for sidecar/single-instance deployments. For multi-instance
/// hosted deployments, replace with a distributed backend implementing the
/// same `check`/`check_and_advance` contract.
#[derive(Debug)]
pub struct FileCounterStore {
    path: PathBuf,
    high_water_mark: u64,
    accepted_digest: Option<String>,
}

impl FileCounterStore {
    pub fn load_or_init(path: &Path) -> Result<Self, CounterStoreError> {
        let high_water_mark = match fs::read_to_string(path) {
            Ok(s) => parse_counter(s.trim()).map_err(|reason| CounterStoreError::Parse {
                path: path.to_path_buf(),
                reason,
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => {
                return Err(CounterStoreError::Read {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        };

        let digest_path = digest_path(path);
        let accepted_digest = match fs::read_to_string(&digest_path) {
            Ok(s) => {
                let (counter, digest) =
                    parse_digest_record(s.trim()).map_err(|reason| CounterStoreError::Parse {
                        path: digest_path.clone(),
                        reason,
                    })?;
                (counter == high_water_mark).then_some(digest)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(CounterStoreError::Read {
                    path: digest_path,
                    source: e,
                });
            }
        };

        Ok(Self {
            path: path.to_path_buf(),
            high_water_mark,
            accepted_digest,
        })
    }

    #[must_use]
    pub fn high_water_mark(&self) -> u64 {
        self.high_water_mark
    }

    /// Payload digest accepted at the high-water mark, when known.
    #[must_use]
    pub fn accepted_digest(&self) -> Option<&str> {
        self.accepted_digest.as_deref()
    }

    /// Decide whether a bundle with `candidate` counter and payload `digest`
    /// may be accepted, without recording anything.
    pub fn check(&self, candidate: u64, digest: &str) -> Result<(), CounterCheckError> {
        if candidate < self.high_water_mark {
            return Err(CounterCheckError::Regression {
                candidate,
                high_water_mark: self.high_water_mark,
            });
        }
        if candidate == self.high_water_mark && self.high_water_mark != 0 {
            if let Some(recorded) = &self.accepted_digest
                && recorded != digest
            {
                return Err(CounterCheckError::ContentMismatch {
                    counter: candidate,
                    recorded_digest: recorded.clone(),
                    candidate_digest: digest.to_string(),
                });
            }
        } else if candidate == self.high_water_mark {
            return Err(CounterCheckError::Regression {
                candidate,
                high_water_mark: self.high_water_mark,
            });
        }
        Ok(())
    }

    /// [`check`](Self::check), then record the acceptance. Re-accepting the
    /// artifact already recorded at the high-water mark writes nothing.
    pub fn check_and_advance(
        &mut self,
        candidate: u64,
        digest: &str,
    ) -> Result<(), CounterCheckError> {
        self.check(candidate, digest)?;
        if candidate == self.high_water_mark && self.accepted_digest.as_deref() == Some(digest) {
            return Ok(());
        }
        let persist = |e| CounterCheckError::Persist {
            path: self.path.clone(),
            source: e,
        };
        if candidate != self.high_water_mark {
            write_atomic(&self.path, &format!("{candidate}\n")).map_err(persist)?;
        }
        write_atomic(&digest_path(&self.path), &format!("{candidate} {digest}\n"))
            .map_err(persist)?;
        self.high_water_mark = candidate;
        self.accepted_digest = Some(digest.to_string());
        Ok(())
    }
}

fn digest_path(counter_path: &Path) -> PathBuf {
    let mut name = counter_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".digest");
    counter_path.with_file_name(name)
}

fn parse_counter(s: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|e| format!("invalid counter `{s}`: {e}"))
}

fn parse_digest_record(s: &str) -> Result<(u64, String), String> {
    let mut fields = s.split_whitespace();
    let (Some(counter), Some(digest), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err(format!("expected `<counter> <sha256-hex>`, got `{s}`"));
    };
    let counter = parse_counter(counter)?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid digest `{digest}`"));
    }
    Ok((counter, digest.to_string()))
}

fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    if !dir.as_os_str().is_empty() {
        fs::create_dir_all(dir)?;
    }
    // Write to a sibling temp file then rename — rename(2) is atomic on the
    // same filesystem so readers never see a half-written value.
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CounterStoreError {
    #[error("could not read counter store {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("counter store {path} is corrupt: {reason}")]
    Parse { path: PathBuf, reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum CounterCheckError {
    #[error("counter regression: candidate {candidate} <= high-water-mark {high_water_mark}")]
    Regression {
        candidate: u64,
        high_water_mark: u64,
    },
    #[error(
        "counter {counter} already accepted with a different artifact: recorded digest {recorded_digest}, candidate digest {candidate_digest}"
    )]
    ContentMismatch {
        counter: u64,
        recorded_digest: String,
        candidate_digest: String,
    },
    #[error("failed to persist counter to {path}: {source}")]
    Persist {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn fresh_install_is_zero() {
        let tmp = TempDir::new().unwrap();
        let store = CounterStore::load_or_init(&tmp.path().join("counter")).unwrap();
        assert_eq!(store.high_water_mark(), 0);
        assert_eq!(store.accepted_digest(), None);
    }

    #[test]
    fn advance_persists_counter_and_digest() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(5, D1).unwrap();
        store.check_and_advance(10, D2).unwrap();
        // Reopen — both survive.
        let store2 = CounterStore::load_or_init(&path).unwrap();
        assert_eq!(store2.high_water_mark(), 10);
        assert_eq!(store2.accepted_digest(), Some(D2));
    }

    #[test]
    fn counter_file_stays_a_single_decimal_line() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(2, D1).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"2\n");
        assert_eq!(
            fs::read_to_string(tmp.path().join("counter.digest")).unwrap(),
            format!("2 {D1}\n")
        );
    }

    #[test]
    fn rejects_regression() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(10, D1).unwrap();
        let err = store.check_and_advance(5, D2).unwrap_err();
        assert!(matches!(err, CounterCheckError::Regression { .. }));
    }

    #[test]
    fn rejects_counter_zero_on_fresh_store() {
        let tmp = TempDir::new().unwrap();
        let store = CounterStore::load_or_init(&tmp.path().join("counter")).unwrap();
        assert!(matches!(
            store.check(0, D1),
            Err(CounterCheckError::Regression { .. })
        ));
    }

    #[test]
    fn accepts_same_counter_with_same_digest_without_rewriting() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(10, D1).unwrap();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        let digest_before = fs::read_to_string(tmp.path().join("counter.digest")).unwrap();

        // Simulate a restart: reload from disk, then re-accept the same artifact.
        let mut restarted = CounterStore::load_or_init(&path).unwrap();
        restarted.check_and_advance(10, D1).unwrap();
        assert_eq!(restarted.high_water_mark(), 10);
        assert_eq!(fs::read(&path).unwrap(), b"10\n");
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
        assert_eq!(
            fs::read_to_string(tmp.path().join("counter.digest")).unwrap(),
            digest_before
        );
    }

    #[test]
    fn rejects_same_counter_with_different_digest() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(10, D1).unwrap();
        let err = store.check_and_advance(10, D2).unwrap_err();
        assert!(matches!(err, CounterCheckError::ContentMismatch { .. }));
        assert_eq!(store.accepted_digest(), Some(D1));
    }

    #[test]
    fn same_counter_with_no_recorded_digest_is_accepted_and_recorded() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        fs::write(&path, "2\n").unwrap();
        let mut store = CounterStore::load_or_init(&path).unwrap();
        assert_eq!(store.accepted_digest(), None);
        store.check_and_advance(2, D1).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"2\n");
        let store2 = CounterStore::load_or_init(&path).unwrap();
        assert_eq!(store2.accepted_digest(), Some(D1));
        assert!(matches!(
            store2.check(2, D2),
            Err(CounterCheckError::ContentMismatch { .. })
        ));
    }

    #[test]
    fn digest_recorded_for_another_counter_is_ignored() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        fs::write(&path, "3\n").unwrap();
        fs::write(tmp.path().join("counter.digest"), format!("2 {D1}\n")).unwrap();
        let store = CounterStore::load_or_init(&path).unwrap();
        assert_eq!(store.high_water_mark(), 3);
        assert_eq!(store.accepted_digest(), None);
    }

    #[test]
    fn rejects_corrupt_counter() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        fs::write(&path, "not-a-number").unwrap();
        let err = CounterStore::load_or_init(&path).unwrap_err();
        assert!(matches!(err, CounterStoreError::Parse { .. }));
    }

    #[test]
    fn rejects_corrupt_digest_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        fs::write(&path, "2\n").unwrap();
        fs::write(tmp.path().join("counter.digest"), "2 not-hex\n").unwrap();
        let err = CounterStore::load_or_init(&path).unwrap_err();
        assert!(matches!(err, CounterStoreError::Parse { .. }));
    }
}
