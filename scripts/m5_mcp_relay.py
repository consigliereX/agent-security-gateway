"""M5: stdio MCP shim for an OMP child trapped in a Bubblewrap namespace.

Connects only to the in-namespace controller; the controller forwards to the
host M4 trusted gateway over its pre-existing one-to-one stdio MCP bridge.
"""
from __future__ import annotations
import socket
import json
import sys


def main() -> int:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(50)
        sock.connect('/tmp/asg-m5-mcp.sock')
        with sock.makefile('rb') as reader:
            for line in sys.stdin.buffer:
                if len(line) > 131073 or not line.endswith(b'\n'):
                    return 2
                sock.sendall(line)
                if 'id' in json.loads(line):
                    response = reader.readline(131074)
                    if not response or len(response) > 131073:
                        return 3
                    sys.stdout.buffer.write(response)
                    sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
