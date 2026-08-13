#!/usr/bin/env python3
"""mini_s3_server.py -- a minimal, stdlib-only S3-compatible server for
AmiSnap's Phase 5 host-CI check (implementation-plan.md): proves
s3.c/sigv4.c/http.c/transport.h's protocol code interoperates with an
INDEPENDENT server implementation, not just the in-memory mock
tests/test_s3.c already covers (which shares this project's own
assumptions about the wire format -- a real, separate implementation is
what actually catches interop bugs). Same reasoning and shape as
tests/webdav/mini_webdav_server.py.

Unlike the WebDAV mock, this one actually VERIFIES the SigV4
Authorization header -- recomputing the canonical request/string-to-
sign/signature from scratch (this file's own independent
implementation of RFC-published SigV4, not a copy of src/core/sigv4.c)
and rejecting a mismatch with 403. That makes this the one host-CI
check that proves AmiSnap's signer produces a signature a genuinely
different, independent SigV4 implementation accepts -- AWS's own
published test vectors (tests/test_sigv4.c) only prove the *signing*
math is right in isolation, not that a real server's *verification*
of a live request agrees.

Backed by a real directory (not in-memory), so a request really does
create/read/delete real files on disk, one file per stored object key
(with '/' in the key mapped straight onto the filesystem, same as
mini_webdav_server.py's own _fs_path()).

Supports exactly the subset s3.c uses: PUT, GET, HEAD, DELETE, and
GET ?list-type=2 (ListObjectsV2, with delimiter/prefix/continuation-
token, real pagination via a small server-side MAX_KEYS). No TLS --
not exercised by this check (s3.c itself has no TLS support yet
either, see s3.h's own doc comment).

Usage: mini_s3_server.py <root-dir> <bucket> <access_key> <secret_key>
       <region> <port (0 = auto-select)> [max_keys]
Prints "READY <port>" to stdout once listening.
"""
import hashlib
import hmac
import http.server
import os
import socketserver
import sys
import urllib.parse

MAX_KEYS_DEFAULT = 1000


def sigv4_signing_key(secret_key, date, region, service):
    def h(key, msg):
        return hmac.new(key, msg.encode("ascii"), hashlib.sha256).digest()
    k_date = h(("AWS4" + secret_key).encode("utf-8"), date)
    k_region = h(k_date, region)
    k_service = h(k_region, service)
    return h(k_service, "aws4_request")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _key_path(self, key):
        # '/' in an S3 key is just another character to a real S3
        # service (keys are flat, not a directory tree) -- but mapping
        # it onto real subdirectories on disk is the simplest faithful
        # backing store, same choice mini_webdav_server.py made for
        # WebDAV collections.
        parts = [p for p in key.split("/") if p not in ("", ".", "..")]
        return os.path.join(self.server.root, *parts) if parts else self.server.root

    def _read_body(self):
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

    def _verify_sigv4(self, method, canonical_uri, canonical_query_string, body_len):
        """Recomputes the canonical request/string-to-sign/signature
        from what was actually received and compares against the
        client's own Authorization header. Returns True/False."""
        authz = self.headers.get("Authorization", "")
        if not authz.startswith("AWS4-HMAC-SHA256 "):
            return False
        # "AWS4-HMAC-SHA256 Credential=AKID/scope, SignedHeaders=a;b;c, Signature=hex"
        parts = {}
        for field in authz[len("AWS4-HMAC-SHA256 "):].split(", "):
            k, _, v = field.partition("=")
            parts[k.strip()] = v.strip()
        credential = parts.get("Credential", "")
        signed_headers_list = parts.get("SignedHeaders", "").split(";")
        client_sig = parts.get("Signature", "")
        cred_parts = credential.split("/")
        if len(cred_parts) != 5:
            return False
        access_key, date, region, service, term = cred_parts
        if access_key != self.server.access_key or term != "aws4_request":
            return False

        date_time = self.headers.get("x-amz-date", "")
        payload_hash = self.headers.get("x-amz-content-sha256", "")

        canonical_headers = ""
        for name in signed_headers_list:
            if name == "host":
                value = self.headers.get("Host", "")
            else:
                value = self.headers.get(name, "")
            # AWS's own documented CanonicalHeaders rule: trim + collapse
            # internal whitespace runs to a single space.
            value = " ".join(value.split())
            canonical_headers += "%s:%s\n" % (name, value)
        signed_headers = ";".join(signed_headers_list)

        creq = "\n".join([
            method, canonical_uri, canonical_query_string,
            canonical_headers.rstrip("\n") + "\n", signed_headers, payload_hash,
        ])
        # Real S3 also validates the payload hash for a signed (non-
        # UNSIGNED-PAYLOAD) body; s3.c always sends UNSIGNED-PAYLOAD, so
        # this mock doesn't re-hash the body -- (void)body_len kept as a
        # parameter for a future signed-payload test rather than removed.
        _ = body_len

        creq_hash = hashlib.sha256(creq.encode("utf-8")).hexdigest()
        scope = "%s/%s/%s/aws4_request" % (date, region, service)
        sts = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (date_time, scope, creq_hash)

        signing_key = sigv4_signing_key(self.server.secret_key, date, region, service)
        expect_sig = hmac.new(signing_key, sts.encode("utf-8"), hashlib.sha256).hexdigest()

        return hmac.compare_digest(expect_sig, client_sig)

    def _parse_path(self):
        parsed = urllib.parse.urlsplit(self.path)
        canonical_uri = parsed.path
        canonical_query_string = parsed.query
        segments = parsed.path.split("/", 2)
        # segments[0] is "" (leading slash); segments[1] is the bucket.
        bucket = segments[1] if len(segments) > 1 else ""
        key = segments[2] if len(segments) > 2 else ""
        return canonical_uri, canonical_query_string, bucket, key

    def _handle(self, method):
        canonical_uri, canonical_query_string, bucket, key = self._parse_path()
        body = self._read_body() if method == "PUT" else b""

        if bucket != self.server.bucket:
            self._respond(404)
            return

        if not self._verify_sigv4(method, canonical_uri, canonical_query_string, len(body)):
            self._respond(403, b"SignatureDoesNotMatch")
            return

        if method == "PUT":
            fs_path = self._key_path(key)
            os.makedirs(os.path.dirname(fs_path) or self.server.root, exist_ok=True)
            with open(fs_path, "wb") as f:
                f.write(body)
            self._respond(200)
            return

        if key == "" and "list-type=2" in canonical_query_string:
            self._list_objects(canonical_query_string)
            return

        fs_path = self._key_path(key)
        if method in ("GET", "HEAD"):
            if not os.path.isfile(fs_path):
                self._respond(404)
                return
            if method == "HEAD":
                self._respond(200)
            else:
                with open(fs_path, "rb") as f:
                    self._respond(200, f.read())
            return

        if method == "DELETE":
            # Real S3's own DELETE is unconditionally "successful"
            # whether or not the key existed -- s3.c's own remove()
            # already accounts for this (a HEAD first).
            if os.path.isfile(fs_path):
                os.remove(fs_path)
            self._respond(204)
            return

        self._respond(400)

    def _list_objects(self, query):
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        prefix = params.get("prefix", [""])[0]
        delimiter = params.get("delimiter", [""])[0]
        continuation = params.get("continuation-token", [""])[0]
        max_keys = self.server.max_keys

        all_keys = []
        for dirpath, _dirnames, filenames in os.walk(self.server.root):
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.server.root).replace(os.sep, "/")
                all_keys.append(rel)
        all_keys.sort()

        matching = [k for k in all_keys if k.startswith(prefix)]
        if delimiter:
            # One level only: collapse anything past the next delimiter
            # (after the prefix) into a CommonPrefixes entry instead of
            # a Contents entry, real S3's own ListObjectsV2 behavior.
            seen_common = []
            contents = []
            for k in matching:
                rest = k[len(prefix):]
                idx = rest.find(delimiter)
                if idx == -1:
                    contents.append(k)
                else:
                    common = prefix + rest[:idx + len(delimiter)]
                    if common not in seen_common:
                        seen_common.append(common)
        else:
            contents = matching
            seen_common = []

        start = 0
        if continuation:
            start = int(continuation)
        page = contents[start:start + max_keys]
        truncated = start + max_keys < len(contents)

        xml = ['<?xml version="1.0" encoding="UTF-8"?>', "<ListBucketResult>"]
        for k in page:
            xml.append("<Contents><Key>%s</Key></Contents>" % k)
        if start == 0:
            for c in seen_common:
                xml.append("<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>" % c)
        xml.append("<IsTruncated>%s</IsTruncated>" % ("true" if truncated else "false"))
        if truncated:
            xml.append("<NextContinuationToken>%d</NextContinuationToken>" % (start + max_keys))
        xml.append("</ListBucketResult>")
        self._respond(200, "".join(xml).encode("utf-8"), "application/xml")

    def do_PUT(self):
        self._handle("PUT")

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_DELETE(self):
        self._handle("DELETE")

    def log_message(self, fmt, *args):
        pass  # keep CI output quiet -- failures are asserted by the driver


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    root = sys.argv[1]
    bucket = sys.argv[2]
    access_key = sys.argv[3]
    secret_key = sys.argv[4]
    region = sys.argv[5]
    port = int(sys.argv[6])
    max_keys = int(sys.argv[7]) if len(sys.argv) > 7 else MAX_KEYS_DEFAULT
    os.makedirs(root, exist_ok=True)
    # ThreadingMixIn: s3.c legitimately holds one HTTP/1.1 keep-alive
    # connection open across several requests while its streaming
    # put_begin/append/finish path issues its own separate PUT --
    # same reasoning mini_webdav_server.py's own header comment
    # documents (confirmed the hard way there, not assumed here).
    server = Server(("127.0.0.1", port), Handler)
    server.root = root
    server.bucket = bucket
    server.access_key = access_key
    server.secret_key = secret_key
    server.region = region
    server.max_keys = max_keys
    print("READY %d" % server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
