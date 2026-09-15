// SPDX-License-Identifier: Apache-2.0

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
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

        let mut file = options.open(&self.path)?;
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
