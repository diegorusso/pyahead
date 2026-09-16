"""Serve the public site for local previews, using only the standard library."""

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Naming each module here meant that adding one served a 404 instead, which
# breaks the page completely: a failed import stops the whole module graph, so
# the page renders nothing at all rather than losing one feature. Every
# top-level module is public anyway, so allow them by extension.
PUBLIC_FILES = {"index.html", "about.html", "styles.css", "favicon.svg"}
PUBLIC_DIRECTORIES = {"vendor", "example"}


class PreviewHandler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".mjs": "text/javascript",
        ".whl": "application/octet-stream",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def send_head(self):
        target = Path(self.translate_path(self.path)).resolve()
        if target == ROOT:
            target = ROOT / "index.html"
        relative = target.relative_to(ROOT) if target.is_relative_to(ROOT) else None
        public = relative is not None and (
            relative.as_posix() in PUBLIC_FILES
            or (len(relative.parts) == 1 and relative.suffix == ".mjs")
            or (relative.parts and relative.parts[0] in PUBLIC_DIRECTORIES)
        )
        if not public or any(part.startswith(".") for part in relative.parts):
            self.send_error(404)
            return None
        return super().send_head()

    def list_directory(self, path):
        self.send_error(404)
        return None

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    options = parser.parse_args()
    with ThreadingHTTPServer((options.bind, options.port), PreviewHandler) as server:
        print(f"PyAhead preview: http://{options.bind}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
