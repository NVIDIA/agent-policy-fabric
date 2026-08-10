// SPDX-License-Identifier: Apache-2.0
//! Persistent monotonic-counter store; rejects bundles whose counter does not increase (anti-rollback).
//!
//! The [`CounterStore`] type alias defaults to the file-based backend.
//! For remote/hosted deployments, swap in a backend that persists to a
//! shared store (Redis, etcd, database) by implementing the same interface.
//!
//! Failure posture: if the backing store is missing the high-water mark is
//! 0 (fresh install). If it exists but is corrupt, loading fails — the
//! operator must intervene rather than risk silent rollback.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Type alias so callers don't couple to the concrete backend.
pub type CounterStore = FileCounterStore;

/// File-backed monotonic counter. Stores the u64 in decimal with
/// atomic write-temp-then-rename. Suitable for sidecar/single-instance
/// deployments. For multi-instance hosted deployments, replace with a
/// distributed backend implementing the same `check_and_advance` contract.
#[derive(Debug)]
pub struct FileCounterStore {
    path: PathBuf,
    high_water_mark: u64,
}

impl FileCounterStore {
    pub fn load_or_init(path: &Path) -> Result<Self, CounterStoreError> {
        let high_water_mark = match fs::read_to_string(path) {
            Ok(s) => parse_value(s.trim()).map_err(|reason| CounterStoreError::Parse {
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
        Ok(Self {
            path: path.to_path_buf(),
            high_water_mark,
        })
    }

    #[must_use]
    pub fn high_water_mark(&self) -> u64 {
        self.high_water_mark
    }

    pub fn check_and_advance(&mut self, candidate: u64) -> Result<(), CounterCheckError> {
        if candidate <= self.high_water_mark {
            return Err(CounterCheckError::Regression {
                candidate,
                high_water_mark: self.high_water_mark,
            });
        }
        write_atomic(&self.path, candidate).map_err(|e| CounterCheckError::Persist {
            path: self.path.clone(),
            source: e,
        })?;
        self.high_water_mark = candidate;
        Ok(())
    }
}

fn parse_value(s: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|e| format!("invalid counter `{s}`: {e}"))
}

fn write_atomic(path: &Path, value: u64) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    if !dir.as_os_str().is_empty() {
        fs::create_dir_all(dir)?;
    }
    // Write to a sibling temp file then rename — rename(2) is atomic on the
    // same filesystem so readers never see a half-written value.
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        writeln!(f, "{value}")?;
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

    #[test]
    fn fresh_install_is_zero() {
        let tmp = TempDir::new().unwrap();
        let store = CounterStore::load_or_init(&tmp.path().join("counter")).unwrap();
        assert_eq!(store.high_water_mark(), 0);
    }

    #[test]
    fn advance_persists() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(5).unwrap();
        store.check_and_advance(10).unwrap();
        // Reopen — value survives.
        let store2 = CounterStore::load_or_init(&path).unwrap();
        assert_eq!(store2.high_water_mark(), 10);
    }

    #[test]
    fn rejects_regression() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(10).unwrap();
        let err = store.check_and_advance(5).unwrap_err();
        assert!(matches!(err, CounterCheckError::Regression { .. }));
    }

    #[test]
    fn rejects_equal() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        let mut store = CounterStore::load_or_init(&path).unwrap();
        store.check_and_advance(10).unwrap();
        assert!(store.check_and_advance(10).is_err());
    }

    #[test]
    fn rejects_corrupt() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("counter");
        fs::write(&path, "not-a-number").unwrap();
        let err = CounterStore::load_or_init(&path).unwrap_err();
        assert!(matches!(err, CounterStoreError::Parse { .. }));
    }
}
