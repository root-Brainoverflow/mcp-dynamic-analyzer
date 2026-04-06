#!/usr/bin/env python3
"""Vulnerable MCP server fixture — no input validation, leaks errors."""

import json
import os
import sys


def handle(request: dict) -> dict | None:
    method = request.get("method")
    req_id = request.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "vulnerable-test-server", "version": "1.0.0"},
        }}

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": [
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            },
            {
                "name": "run_query",
                "description": "Run a database query",
                "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}},
            },
        ]}}

    if method == "tools/call":
        params = request.get("params", {})
        tool = params.get("name", "")
        args = params.get("arguments", {})

        if tool == "read_file":
            path = args.get("path", "")
            try:
                content = open(path).read()  # noqa: SIM115 — intentionally vulnerable
                return {"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": content}],
                }}
            except Exception as e:
                return {"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": f"Error: {e}"}],
                }}

        if tool == "run_query":
            sql = args.get("sql", "")
            return {"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": f"Query executed: {sql}\nSQLite3.OperationalError: near syntax error"}],
            }}

        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Unknown tool"}}

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        response = handle(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
