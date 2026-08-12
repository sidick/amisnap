/* base64.h -- RFC 4648 base64 encoding. The one place this codebase
 * needs it so far is webdav.c's HTTP Basic Authorization header
 * (docs/proposal.md Tier 2); encoding only -- nothing here needs to
 * decode base64 (the .uaem sidecar format and format.md's own TLV
 * encoding are unrelated to it).
 */
#ifndef AMISNAP_BASE64_H
#define AMISNAP_BASE64_H

#include <stddef.h>

#include "tlv.h"

/* Appends the base64 encoding of data/len to `out` (an already-
 * amisnap_buf_init()'d growable buffer, appended not reset, same
 * convention as amisnap_buf_bytes()). Standard alphabet
 * (A-Za-z0-9+/), '=' padding, no line wrapping (RFC 4648 sec 4 --
 * MIME's 76-column wrapping is a different, unrelated encoding this
 * doesn't need). Returns AMISNAP_OK or AMISNAP_ERR_NOMEM. */
int amisnap_base64_encode(amisnap_buf *out, const void *data, size_t len);

#endif /* AMISNAP_BASE64_H */
