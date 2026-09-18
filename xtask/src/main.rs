// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
mod dag_guard;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("dag-guard") => {
            if let Err(e) = dag_guard::run() {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Usage: cargo xtask dag-guard");
            std::process::exit(1);
        }
    }
}
