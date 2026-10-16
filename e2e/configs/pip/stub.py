#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Loopback HTTP stub behind the verification run's policy information provider.

GET /healthz                 -> 200 {"ok": true}
GET /table/<name>?<col>=<v>  -> 200 {"result": [{<col>: <v>, ..., "state": "active"}]}

Binds 127.0.0.1 only: it runs as a sidecar in the APF pod and the gateway
reaches it over the pod's loopback.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/healthz":
            return self._json(200, {"ok": True})
        if parts.path.startswith("/table/"):
            row = dict(parse_qsl(parts.query))
            row.setdefault("state", "active")
            return self._json(200, {"result": [row]})
        return self._json(404, {"error": {"message": "not found"}})

    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write("pip-stub " + fmt % args + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=19500)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    sys.stderr.write(f"pip-stub listening on 127.0.0.1:{args.port}\n")
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
