#!/usr/bin/env sh
# Build the encrypted pages, then serve them locally for preview.
# Usage: ./dev.sh [port]   (port defaults to 8000)
#
# Serves with Cache-Control: no-store. Every build re-encrypts EVERY file with
# a fresh key, so a browser mixing a cached file from build N with a fresh file
# from build N+1 gets an AES-GCM DOMException. no-store makes that impossible.
cd "$(dirname "$0")" || exit 1
PORT="${1:-8000}"

python build.py || exit 1

echo
echo "Serving at http://localhost:${PORT}/   (Ctrl-C to stop)"
python - "$PORT" << 'EOF'
import http.server, sys

class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, must-revalidate")
        super().end_headers()

http.server.ThreadingHTTPServer(("", int(sys.argv[1])), NoCacheHandler).serve_forever()
EOF
