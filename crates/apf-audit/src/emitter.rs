// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::events::TypedAuditEvent;
use crate::model::{AuditContext, AuditEvent};
use crate::sanitization::{SanitizationError, SanitizationGuard};
use crate::validation::ValidationError;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("{0}")]
    Validation(#[from] ValidationError),
    #[error("audit sink io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Sanitization(#[from] SanitizationError),
    #[error("audit serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("audit sink lock poisoned: {0}")]
    Lock(String),
}

pub trait AuditSink: Send + Sync {
    fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

#[derive(Debug, Clone)]
pub struct JsonlSink {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl JsonlSink {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open the sink once so a misconfigured path fails at startup rather than
    /// taking a fail-closed producer down at its first event.
    ///
    /// Opens for append exactly as `write_event` does. `write_event` also asks for
    /// read access, but degrades without it, so this stays the real gate. Writes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the parent cannot be created or the file
    /// cannot be opened for appending.
    pub fn preflight(&self) -> Result<(), AuditError> {
        if let Some(parent) = self.path.parent() {
            create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        options.open(&self.path)?;
        Ok(())
    }
}

/// Whether the file has content that does not end in a newline.
///
/// Never fails the write: rotation can truncate the file between the size and
/// the read, and this guard must not be the reason a record is lost.
fn ends_mid_line(file: &mut File) -> bool {
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return false;
    };
    if len == 0 {
        return false;
    }
    if file.seek(SeekFrom::Start(len - 1)).is_err() {
        return false;
    }
    let mut last = [0u8; 1];
    file.read_exact(&mut last).is_ok() && last[0] != b'\n'
}

impl AuditSink for JsonlSink {
    fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        event.validate()?;
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');

        if let Some(parent) = self.path.parent() {
            create_dir_all(parent)?;
        }

        let _guard = self
            .lock
            .lock()
            .map_err(|error| AuditError::Lock(error.to_string()))?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);

        // Read access is only for the guard below, so a write-only log file —
        // a normal hardening choice — must still work.
        let mut file = match options.read(true).open(&self.path) {
            Ok(mut file) => {
                // A partial write leaves an unterminated line; appending after
                // it splices this record onto the broken one, losing both.
                // Same sink instance only: the lock is per-`JsonlSink`, so it
                // sees neither another instance on this path nor another
                // process. Cross-process this can splice a newline into an
                // in-flight write rather than repair one.
                if ends_mid_line(&mut file) {
                    file.write_all(b"\n")?;
                }
                file
            }
            Err(_) => options.read(false).open(&self.path)?,
        };
        file.write_all(&line)?;
        file.flush()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AuditEmitter<S> {
    sink: S,
    sanitizer: SanitizationGuard,
}

impl<S> AuditEmitter<S>
where
    S: AuditSink,
{
    #[must_use]
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            sanitizer: SanitizationGuard::new(),
        }
    }

    #[must_use]
    pub fn with_sanitizer(sink: S, sanitizer: SanitizationGuard) -> Self {
        Self { sink, sanitizer }
    }

    pub fn emit_required(&self, event: &AuditEvent) -> Result<(), AuditError> {
        event.validate()?;
        self.sanitizer.check(event)?;
        self.sink.write_event(event)
    }

    pub fn emit_typed_required<E>(
        &self,
        ctx: &AuditContext,
        event: E,
    ) -> Result<AuditEvent, AuditError>
    where
        E: TypedAuditEvent,
    {
        let event = event.into_audit_event(ctx)?;
        self.emit_required(&event)?;
        Ok(event)
    }

    #[must_use]
    pub fn emit_best_effort(&self, event: &AuditEvent) -> EmitOutcome {
        match self.emit_required(event) {
            Ok(()) => EmitOutcome::Written,
            Err(error) => EmitOutcome::Failed(error.to_string()),
        }
    }

    #[must_use]
    pub fn sink(&self) -> &S {
        &self.sink
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitOutcome {
    Written,
    Failed(String),
}
