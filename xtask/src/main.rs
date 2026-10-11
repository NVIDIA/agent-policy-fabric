// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
mod dag_guard;
mod vendor_protos;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(|s| s.as_str()) {
        Some("dag-guard") => dag_guard::run(),
        Some("vendor-protos") => {
            let check = args.get(2).map(|s| s.as_str()) == Some("--check");
            vendor_protos::run(check)
        }
        _ => {
            eprintln!("Usage: cargo xtask dag-guard | cargo xtask vendor-protos [--check]");
            std::process::exit(1);
        }
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
