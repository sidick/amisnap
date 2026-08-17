#!/usr/bin/env python3
"""mini_webdav_server.py -- a minimal, stdlib-only WebDAV server for
AmiSnap's Phase 3 item 5 host-CI check (implementation-plan.md): proves
webdav.c/http.c/transport.h's protocol code interoperates with an
INDEPENDENT server implementation, not just the in-memory mock
tests/test_webdav.c already covers (which shares this project's own
assumptions about the wire format -- a real, separate implementation is
what actually catches interop bugs).

Backed by a real directory (not in-memory), so a request really does
create/read/delete real files/directories on disk.

Supports exactly the subset webdav.c uses: PUT, GET, DELETE, MKCOL,
PROPFIND (Depth 0/1), both Content-Length and chunked Transfer-Encoding
request bodies (decoded by hand -- BaseHTTPRequestHandler does not do
this itself). No auth, no locking -- neither is exercised by this
check (auth is already covered against the in-memory mock in
tests/test_webdav.c).

Usage: mini_webdav_server.py <root-dir> <port (0 = auto-select)> [cert key]
Prints "READY <port>" to stdout once listening, so a driving script can
synchronize on the actual bound port instead of guessing one free or
guessing a startup delay.

Optional TLS: pass a cert and key (PEM paths) as two extra arguments to
wrap the listening socket in a real TLS session (Python's stdlib ssl
module -- an independent TLS implementation from AmiSSL, same
"independent implementation, not this project's own assumptions"
reasoning as everything else in this file) instead of plain HTTP.
Added for implementation-plan.md Phase 3 item 4's own on-target
`run-tls-bench.sh` follow-up work: a real end-to-end SNAPSHOT/RESTORE
cycle over a real https:// REPO= against the real, unmodified
production CLI and webdav.c, not just a raw handshake. Omit both
arguments for the original plain-HTTP behaviour (host-CI's own
webdav-check, unaffected either way).
"""
import http.server
import os
import socketserver
import ssl
import sys
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _fs_path(self):
        path = urllib.parse.unquote(self.path)
        path = path.lstrip("/")
        # Reject any path component escaping the root ("..") -- cheap
        # hardening, not load-bearing for this test, but means a coding
        # mistake in the client under test can never write outside root.
        parts = [p for p in path.split("/") if p not in ("", ".", "..")]
        return os.path.join(self.server.root, *parts) if parts else self.server.root

    def _read_body(self):
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            body = b""
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()  # trailing CRLF after the terminating chunk
                    break
                body += self.rfile.read(size)
                self.rfile.read(2)  # CRLF after each chunk's data
            return body
        cl = self.headers.get("Content-Length")
        if cl:
            return self.rfile.read(int(cl))
        return b""

    def _respond(self, code, body=b"", content_type=None):
        self.send_response(code)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_PUT(self):
        body = self._read_body()
        fs_path = self._fs_path()
        parent = os.path.dirname(fs_path)
        if not os.path.isdir(parent):
            self._respond(409)
            return
        with open(fs_path, "wb") as f:
            f.write(body)
        self._respond(201)

    def do_GET(self):
        fs_path = self._fs_path()
        if not os.path.isfile(fs_path):
            self._respond(404)
            return
        with open(fs_path, "rb") as f:
            self._respond(200, f.read())

    def do_DELETE(self):
        fs_path = self._fs_path()
        if os.path.isfile(fs_path):
            os.remove(fs_path)
            self._respond(204)
        elif os.path.isdir(fs_path):
            os.rmdir(fs_path)
            self._respond(204)
        else:
            self._respond(404)

    def do_MKCOL(self):
        self._read_body()
        fs_path = self._fs_path()
        if os.path.exists(fs_path):
            self._respond(405)
            return
        parent = os.path.dirname(fs_path)
        if not os.path.isdir(parent):
            self._respond(409)
            return
        os.mkdir(fs_path)
        self._respond(201)

    def do_PROPFIND(self):
        self._read_body()
        depth = self.headers.get("Depth", "0")
        fs_path = self._fs_path()
        url_path = urllib.parse.unquote(self.path)
        if not os.path.exists(fs_path):
            self._respond(404)
            return
        is_dir = os.path.isdir(fs_path)
        entries = ['<D:response><D:href>%s%s</D:href></D:response>' %
                   (url_path, "/" if is_dir else "")]
        if is_dir and depth == "1":
            base = url_path if url_path.endswith("/") else url_path + "/"
            for name in sorted(os.listdir(fs_path)):
                child_fs = os.path.join(fs_path, name)
                suffix = "/" if os.path.isdir(child_fs) else ""
                entries.append('<D:response><D:href>%s%s%s</D:href></D:response>' %
                                (base, name, suffix))
        xml = ('<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">' +
               "".join(entries) + "</D:multistatus>").encode("utf-8")
        self._respond(207, xml, "application/xml")

    def log_message(self, fmt, *args):
        pass  # keep CI output quiet -- failures are asserted by the driver, not read from this log


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    root = sys.argv[1]
    port = int(sys.argv[2])
    cert = sys.argv[3] if len(sys.argv) > 3 else None
    key = sys.argv[4] if len(sys.argv) > 4 else None
    os.makedirs(root, exist_ok=True)
    # ThreadingMixIn, not plain HTTPServer/TCPServer: webdav.c legitimately
    # holds one HTTP/1.1 keep-alive connection open across several
    # requests (proposal.md's own "keep-alive" requirement) while its
    # streaming put_begin/put_append/put_finish trio opens a SEPARATE,
    # concurrent connection for a chunked upload -- a single-threaded
    # server can only ever service one connection's request loop at a
    # time, so it would block forever inside the first (still-open,
    # idle) connection's next-request read and never even accept the
    # second. Confirmed the hard way: a plain TCPServer here made
    # live_test.c hang indefinitely on its first chunked upload, not a
    # bug in webdav.c itself.
    server = Server(("127.0.0.1", port), Handler)
    server.root = root
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("READY %d" % server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
