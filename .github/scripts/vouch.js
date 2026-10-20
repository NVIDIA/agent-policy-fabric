// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Shared VOUCHED.td parser for the vouch-check and vouch-command workflows.
// Both load it from the default branch, never from a pull request branch.

// A name prefixed with "-" is denounced; a denounce wins over any vouch line.
function parseVouched(content) {
  const vouched = new Set();
  const denounced = new Set();
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('-')) denounced.add(line.slice(1).trim().toLowerCase());
    else vouched.add(line.toLowerCase());
  }
  return { vouched, denounced };
}

function isDenounced(content, username) {
  return parseVouched(content).denounced.has(username.toLowerCase());
}

function isVouched(content, username) {
  const { vouched, denounced } = parseVouched(content);
  const name = username.toLowerCase();
  return vouched.has(name) && !denounced.has(name);
}

module.exports = { parseVouched, isDenounced, isVouched };
