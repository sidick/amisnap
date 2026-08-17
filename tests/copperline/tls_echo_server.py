#!/usr/bin/env python3
"""tls_echo_server.py -- minimal TLS echo server for AmiSnap's bulk-
cipher throughput benchmark (implementation-plan.md Phase 3 item 4's
own follow-up: is a cipher override worth adding for slower Amigas'
CPU budget, not security/interop -- proposal.md's own CPU-budget
principle). Echoes back every byte it receives, real TLS termination
via Python's own independent ssl module (not AmiSSL tested against
itself), so tests/copperline/tlsthroughput.c can pump a known amount
of data through a real cipher and time only the transfer, not a
made-up number.

Supports both PSK (no certificate, isolates bulk-cipher cost from key
exchange/certificate verification entirely -- what most of this
benchmark actually wants to measure) and certificate-based ciphers, to
also get real, realistic handshake-plus-transfer numbers for the
ciphers an actual https:// destination would use.

Usage: tls_echo_server.py <port> [cert key] [psk_hex]
Prints "READY <port>" once listening. At least one of (cert,key) or
psk_hex must be given.
"""
import socket
import ssl
import sys
import threading


def handle(conn):
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
    except (ssl.SSLError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1])
    cert = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "-" else None
    key = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None
    psk_hex = sys.argv[4] if len(sys.argv) > 4 else None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    if psk_hex:
        # Offer every PSK suite -- the client (tlsthroughput.c) is the
        # one restricting to a single exact cipher per run via its own
        # SSL_CTX_set_cipher_list(), so the server just needs to make
        # whichever one is being tested available.
        ctx.set_ciphers("PSK")
        psk_bytes = bytes.fromhex(psk_hex)
        # Public API since Python 3.13 -- identity_hint is advisory
        # only; return the pre-shared key for any identity the client
        # offers (this benchmark's own client always offers the one
        # fixed test identity/key pair).
        ctx.set_psk_server_callback(lambda identity: psk_bytes, "amisnap-bench")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    print("READY %d" % sock.getsockname()[1], flush=True)

    while True:
        raw_conn, _ = sock.accept()
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError:
            raw_conn.close()
            continue
        t = threading.Thread(target=handle, args=(conn,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
