#!/usr/bin/env python3
"""Benign MCP server fixture — well-behaved, no vulnerabilities."""

import json
import sys


def handle(request: dict) -> dict | None:
    method = request.get("method")
    req_id = request.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "benign-test-server", "version": "1.0.0"},
        }}

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": [
            {"name": "greet", "description": "Say hello", "inputSchema": {
                "type": "object", "properties": {"name": {"type": "string"}},
            }},
        ]}}

    if method == "tools/call":
        name = request.get("params", {}).get("arguments", {}).get("name", "world")
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": f"Hello, {name}!"}],
        }}

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
