"""Static loopback server for the workbench; it has no device API."""

from __future__ import annotations

import argparse
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
HOST = "127.0.0.1"
DEFAULT_PORT = 38459


class LocalHTTPServer(ThreadingHTTPServer):
    # Do not let this app share its port with another process bound to 0.0.0.0.
    allow_reuse_address = False


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, format_string, *args):
        # The desktop build runs without a console; keep request logs out of app data.
        return


def serve(port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    return LocalHTTPServer((HOST, port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the RK Research Workbench on this PC.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    server = serve(args.port)
    print(f"RK Research Workbench: http://{HOST}:{server.server_address[1]}")
    print("Static files only. HID reports are never opened or sent.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
