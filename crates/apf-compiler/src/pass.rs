// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Target-independent IR pass infrastructure.
//!
//! A `Pass` takes a mutable reference to the canonical IR and transforms it
//! in place. Passes run after the frontend and before any backend; their
//! output is substrate-neutral. The pipeline is empty for v0.

use apf_proto::ir;

#[derive(Debug, thiserror::Error)]
#[error("pass '{name}': {cause}")]
pub struct PassError {
    pub name: String,
    pub cause: String,
}

pub trait Pass: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self, ir: &mut ir::SandboxPolicy) -> Result<(), PassError>;
}

#[derive(Default)]
pub struct PassPipeline(Vec<Box<dyn Pass>>);

impl PassPipeline {
    pub fn add(&mut self, pass: Box<dyn Pass>) {
        self.0.push(pass);
    }

    pub fn run(&self, ir: &mut ir::SandboxPolicy) -> Result<(), PassError> {
        for pass in &self.0 {
            pass.run(ir)?;
        }
        Ok(())
    }
}
