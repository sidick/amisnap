/* webdav.h -- the WebDAV backend (docs/proposal.md "Tier 2 -- WebDAV
 * over HTTP(S)", implementation-plan.md Phase 3 item 3): an
 * amisnap_backend_ops implementation over http.h (request/response
 * protocol) and transport.h (the abstract byte-stream connection) --
 * PUT/GET/MKCOL/DELETE/PROPFIND mapped onto backend.h's put/get/mkcol/
 * remove/exists/list, plus the streaming put_begin/put_append/
 * put_finish/put_abort trio (added for restore.c's chunked-file
 * memory-bounded restore, Phase 2 item 7) implemented as a real
 * chunked-Transfer-Encoding upload -- so a large chunked restore stays
 * memory-bounded end to end over WebDAV too, not just on the directory
 * backend.
 *
 * Deliberately built against transport.h's abstract interface only,
 * never bsdsocket.library or any host sockets API directly -- this
 * keeps webdav.c itself portable (module map: listed under src/core/,
 * not src/amiga/) and host-testable via a mock transport
 * (tests/test_webdav.c), with the real network connection supplied by
 * whatever links this in: src/amiga/socket.c's
 * amisnap_bsdsocket_transport_ops on the real target, a POSIX transport
 * under tests/ for Phase 3 item 5's "host CI runs the protocol code
 * against a local WebDAV container" (not built yet).
 */
#ifndef AMISNAP_WEBDAV_H
#define AMISNAP_WEBDAV_H

#include <stdint.h>

#include "backend.h"
#include "transport.h"

/* Generous fixed bound on base_path + key length this implementation
 * builds real request paths within, same convention and same limit as
 * backend_dir.h's AMISNAP_BACKEND_DIR_MAX_PATH -- a key exceeding it
 * fails with AMISNAP_ERR_MALFORMED rather than overflowing a buffer. */
#define AMISNAP_WEBDAV_MAX_PATH 1024

typedef struct {
    const char *host;      /* hostname or dotted-quad, never NULL */
    uint16_t port;
    /* URL path prefix the repository is rooted at: "" (server root) or
     * "/dav/amisnap" form (leading slash, no trailing slash) --
     * mirrors backend_dir's own `root` parameter, just as a URL path
     * instead of a filesystem path. */
    const char *base_path;
    /* HTTP Basic auth; both NULL = no Authorization header sent. */
    const char *username;
    const char *password;
} amisnap_webdav_config;

/* `transport` is borrowed (must outlive `out`, same convention as
 * amisnap_repo_writer_init's borrowed `be`) -- every connection this
 * backend opens goes through it. Ensures `base_path` exists (MKCOL,
 * tolerating "already exists") before returning, mirroring
 * amisnap_backend_dir_open()'s own mkdir_p(root) at open time. Returns
 * AMISNAP_OK with *out populated (ops + an owned context later released
 * by amisnap_backend_close()), or a negative AMISNAP_ERR_* code. */
int amisnap_backend_webdav_open(const amisnap_webdav_config *cfg, amisnap_transport *transport,
                                 amisnap_backend *out);

#endif /* AMISNAP_WEBDAV_H */
