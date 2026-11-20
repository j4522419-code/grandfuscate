"""Tiny local preview server for direct download links.

Serves only the `download/` directory. ZIP files are sent as attachments so a
browser click downloads them instead of trying to preview binary data.
"""
from __future__ import annotations

import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "download")
PORT = int(os.environ.get("DOWNLOAD_PORT", "8012"))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self) -> None:
        path = urlsplit(self.path).path
        name = os.path.basename(path)
        if name.endswith(".zip"):
            self.send_header(
                "Content-Disposition", f'attachment; filename="{name}"'
            )
            self.send_header("Content-Type", "application/zip")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def list_directory(self, path):
        self.send_error(404, "directory listing disabled")
        return None


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    if not os.path.isdir(ROOT):
        raise SystemExit(f"missing download directory: {ROOT}")
    server = Server(("0.0.0.0", PORT), Handler)
    print(f"download server listening on 0.0.0.0:{PORT}", flush=True)
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
