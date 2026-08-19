/* repo.c -- see repo.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake2s.h"
#include "compress.h"
#include "repo.h"
#include "xxhash32.h"

#define SNAPID_KEY_LEN 32   /* "snapshots/" + 16 + ".mf" + NUL, generous */

static const char HEXD[] = "0123456789abcdef";

void amisnap_repo_object_key(const uint8_t hash[32], char out[AMISNAP_OBJECT_KEY_LEN])
{
    char hex[65];
    size_t i;

    for (i = 0; i < 32; i++) {
        hex[i * 2]     = HEXD[hash[i] >> 4];
        hex[i * 2 + 1] = HEXD[hash[i] & 0x0Fu];
    }
    hex[64] = '\0';
    snprintf(out, AMISNAP_OBJECT_KEY_LEN, "objects/%c%c/%s", hex[0], hex[1], hex);
}

static void snapid_encode(uint32_t days, uint16_t mins, uint16_t ticks, char out[17])
{
    uint8_t raw[8];
    size_t i;

    amisnap_put_be32(raw, days);
    amisnap_put_be16(raw + 4, mins);
    amisnap_put_be16(raw + 6, ticks);
    for (i = 0; i < 8; i++) {
        out[i * 2]     = HEXD[raw[i] >> 4];
        out[i * 2 + 1] = HEXD[raw[i] & 0x0Fu];
    }
    out[16] = '\0';
}

void amisnap_repo_writer_init(amisnap_repo_writer *rw, amisnap_backend *be,
                               const amisnap_repo_subkeys *subkeys)
{
    rw->be = be;
    amisnap_manifest_writer_init(&rw->mw);
    rw->snap_days = rw->snap_mins = rw->snap_ticks = 0;
    rw->have_snap = 0;
    rw->subkeys = subkeys;
    rw->objcomp = AMISNAP_OBJCOMP_RAW;
    rw->comp_alg = AMISNAP_COMP_STORED;
}

void amisnap_repo_writer_set_compression(amisnap_repo_writer *rw, uint8_t comp_alg)
{
    rw->objcomp = AMISNAP_OBJCOMP_FRAMED;
    rw->comp_alg = comp_alg;
}

void amisnap_repo_writer_free(amisnap_repo_writer *rw)
{
    amisnap_manifest_writer_free(&rw->mw);
}

int amisnap_repo_writer_snap(amisnap_repo_writer *rw, const amisnap_snap_meta *snap)
{
    int rc = amisnap_manifest_writer_snap(&rw->mw, snap);
    if (rc != AMISNAP_OK) return rc;

    rw->snap_days = snap->created_days;
    rw->snap_mins = snap->created_mins;
    rw->snap_ticks = snap->created_ticks;
    rw->have_snap = 1;
    return AMISNAP_OK;
}

int amisnap_repo_writer_volume(amisnap_repo_writer *rw, const amisnap_volume_meta *vol)
{
    return amisnap_manifest_writer_volume(&rw->mw, vol);
}

/* Shared by both amisnap_repo_writer_file() and the chunked writer
 * below: hashes, dedup-checks, and (if genuinely new) writes one
 * content object, filling in its content_ref. Never touches the
 * manifest -- callers assemble the entry's own E_CONTENT list from
 * however many of these they need (one whole-file object, or several
 * chunks).
 *
 * `subkeys` NULL writes the object body as-is (CIPHER 0). Non-NULL
 * encrypts it first (format.md "Encryption ... Objects": nonce||
 * ciphertext||mac) -- the object's *name* is still the plaintext
 * hash (dedup and content-addressing stay plaintext-identity, per
 * that same section), only the stored bytes and ref_out->size (still
 * the plaintext length -- callers/readers need that to know how much
 * plaintext to expect after decrypting) differ from the CIPHER 0
 * path.
 *
 * In a FRAMED repository (rw->objcomp) the object body is the
 * compress.h frame around `data` rather than `data` itself --
 * compress-then-encrypt, and the hash/dedup identity is still the
 * uncompressed `data`. The dedup existence check is unchanged: an
 * object already present keeps whatever frame its original writer
 * gave it (the frame is self-describing precisely so this is safe). */
static int write_object(const amisnap_repo_writer *rw,
                         const void *data, size_t len, amisnap_content_ref *ref_out)
{
    amisnap_backend *be = rw->be;
    const amisnap_repo_subkeys *subkeys = rw->subkeys;
    uint8_t hash[32];
    char key[AMISNAP_OBJECT_KEY_LEN];
    amisnap_buf framed;
    const void *body = data;
    size_t bodylen = len;
    int rc;

    amisnap_blake2s256(data, len, hash);
    amisnap_repo_object_key(hash, key);
    amisnap_buf_init(&framed);

    rc = amisnap_backend_exists(be, key);
    if (rc < 0) return rc;
    if (rc == 0) {
        /* Object genuinely new: write it. rc == 1 (already present)
         * skips this entirely -- format.md "Objects already present
         * are never rewritten." */
        if (rw->objcomp == AMISNAP_OBJCOMP_FRAMED) {
            rc = amisnap_frame_encode(rw->comp_alg, (const uint8_t *)data, len, &framed);
            if (rc != AMISNAP_OK) return rc;
            body = framed.data;
            bodylen = framed.len;
        }
        if (subkeys) {
            uint8_t nonce[AMISNAP_REPO_NONCE_SIZE];
            size_t framelen = AMISNAP_REPO_NONCE_SIZE + bodylen + AMISNAP_REPO_MAC_SIZE;
            uint8_t *frame = (uint8_t *)malloc(framelen);
            if (!frame) { amisnap_buf_free(&framed); return AMISNAP_ERR_NOMEM; }

            amisnap_repo_object_nonce(subkeys->nonce, hash, nonce);
            amisnap_repo_encrypt_frame(subkeys, nonce, (const uint8_t *)body, bodylen, frame);
            rc = amisnap_backend_put(be, key, frame, framelen);
            free(frame);
        } else {
            rc = amisnap_backend_put(be, key, body, bodylen);
        }
        amisnap_buf_free(&framed);
        if (rc != AMISNAP_OK) return rc;
    }

    memcpy(ref_out->hash, hash, 32);
    ref_out->size = len;
    return AMISNAP_OK;
}

int amisnap_repo_writer_file(amisnap_repo_writer *rw, amisnap_entry_meta *entry,
                              const void *data, size_t len)
{
    amisnap_content_ref ref;
    int rc;

    if (entry->type != AMISNAP_ETYPE_FILE)
        return AMISNAP_ERR_MALFORMED;

    entry->has_size = 1;
    entry->size = len;

    /* format.md E_XHASH: "advisory accelerator for the paranoid-verify
     * and dedup fast paths; readers never trust it for integrity" --
     * computed here, on every file, unconditionally (not just under a
     * future paranoid-verify mode), since it's near-memory-speed
     * (docs/proposal.md's own CPU-budget case for using it freely) and
     * without it stored now, a later paranoid check would have nothing
     * from this snapshot to compare against. */
    entry->has_xhash = 1;
    entry->xhash = amisnap_xxh32(data, len, 0);

    if (len == 0) {
        entry->content = NULL;
        entry->content_count = 0;
        return amisnap_manifest_writer_entry(&rw->mw, entry);
    }

    rc = write_object(rw, data, len, &ref);
    if (rc != AMISNAP_OK) return rc;

    entry->content = &ref;
    entry->content_count = 1;

    return amisnap_manifest_writer_entry(&rw->mw, entry);
}

int amisnap_repo_writer_file_chunked(amisnap_repo_writer *rw, amisnap_entry_meta *entry,
                                      uint64_t total_size, size_t chunk_size,
                                      int (*read_fn)(void *ctx, void *buf, size_t want, size_t *got),
                                      void *ctx)
{
    uint8_t *buf;
    amisnap_content_ref *refs = NULL;
    size_t ref_count = 0, ref_cap = 0;
    amisnap_xxh32_state xh;
    uint64_t remaining;
    int rc = AMISNAP_OK;

    if (entry->type != AMISNAP_ETYPE_FILE) return AMISNAP_ERR_MALFORMED;
    if (chunk_size == 0) return AMISNAP_ERR_MALFORMED;

    buf = (uint8_t *)malloc(chunk_size);
    if (!buf) return AMISNAP_ERR_NOMEM;

    amisnap_xxh32_init(&xh, 0);
    remaining = total_size;

    while (remaining > 0) {
        size_t want = (remaining < (uint64_t)chunk_size) ? (size_t)remaining : chunk_size;
        size_t got = 0;
        amisnap_content_ref *newarr;

        rc = read_fn(ctx, buf, want, &got);
        if (rc != AMISNAP_OK) goto out;
        if (got == 0) break; /* early EOF -- total_size was optimistic; not an error here */

        amisnap_xxh32_update(&xh, buf, got);

        if (ref_count == ref_cap) {
            size_t newcap = ref_cap ? ref_cap * 2 : 4;
            newarr = (amisnap_content_ref *)realloc(refs, newcap * sizeof(*newarr));
            if (!newarr) { rc = AMISNAP_ERR_NOMEM; goto out; }
            refs = newarr;
            ref_cap = newcap;
        }

        rc = write_object(rw, buf, got, &refs[ref_count]);
        if (rc != AMISNAP_OK) goto out;
        ref_count++;

        remaining -= got;
        if (got < want) break; /* short read == EOF, same as got==0 above */
    }

    entry->has_size = 1;
    entry->size = total_size - remaining;
    entry->has_xhash = 1;
    entry->xhash = amisnap_xxh32_digest(&xh);
    entry->content = refs;
    entry->content_count = ref_count;

    rc = amisnap_manifest_writer_entry(&rw->mw, entry);

out:
    free(buf);
    free(refs);
    return rc;
}

int amisnap_repo_writer_entry(amisnap_repo_writer *rw, const amisnap_entry_meta *entry)
{
    return amisnap_manifest_writer_entry(&rw->mw, entry);
}

int amisnap_repo_writer_finish(amisnap_repo_writer *rw, char snapid_out[17])
{
    amisnap_buf manifest_bytes;
    char snapid[17];
    char key[SNAPID_KEY_LEN];
    uint32_t mins, ticks;
    unsigned attempts;
    int rc;

    if (!rw->have_snap)
        return AMISNAP_ERR_MISSING_FIELD;

    rc = amisnap_manifest_writer_finish(&rw->mw, &manifest_bytes);
    if (rc != AMISNAP_OK) return rc;

    mins = rw->snap_mins;
    ticks = rw->snap_ticks;

    for (attempts = 0; ; attempts++) {
        int exists;

        snapid_encode(rw->snap_days, (uint16_t)mins, (uint16_t)ticks, snapid);
        snprintf(key, SNAPID_KEY_LEN, "snapshots/%s.mf", snapid);

        exists = amisnap_backend_exists(rw->be, key);
        if (exists < 0) { amisnap_buf_free(&manifest_bytes); return exists; }
        if (!exists) break;

        /* Two snapshots landing in the exact same tick: format.md
         * "the writer increments ticks until free". Bounded so a
         * pathological repository can't hang here forever; genuinely
         * unreachable in practice (it would require 65536 collisions
         * in one tick). */
        if (attempts >= 0xFFFFu) { amisnap_buf_free(&manifest_bytes); return AMISNAP_ERR_MALFORMED; }
        if (ticks == 0xFFFFu) { ticks = 0; mins = (uint32_t)(mins + 1); }
        else { ticks++; }
    }

    if (rw->subkeys) {
        /* format.md "Encryption ... Manifests": same nonce||ciphertext||
         * mac framing as objects, applied to the whole file after the
         * common header, with flags bit 0 set to mark it. */
        amisnap_buf encrypted;
        uint8_t nonce[AMISNAP_REPO_NONCE_SIZE];
        size_t plainlen = manifest_bytes.len - 8; /* past the common header */
        size_t framelen = AMISNAP_REPO_NONCE_SIZE + plainlen + AMISNAP_REPO_MAC_SIZE;
        uint8_t *frame = (uint8_t *)malloc(framelen);

        if (!frame) { amisnap_buf_free(&manifest_bytes); return AMISNAP_ERR_NOMEM; }

        amisnap_repo_manifest_nonce(rw->subkeys->nonce, (const uint8_t *)snapid, 16, nonce);
        amisnap_repo_encrypt_frame(rw->subkeys, nonce, manifest_bytes.data + 8, plainlen, frame);
        amisnap_buf_free(&manifest_bytes);

        amisnap_buf_init(&encrypted);
        rc = amisnap_write_header(&encrypted, AMISNAP_FTYPE_MANIFEST, 1);
        if (rc == AMISNAP_OK)
            rc = amisnap_buf_bytes(&encrypted, frame, framelen);
        free(frame);
        if (rc != AMISNAP_OK) { amisnap_buf_free(&encrypted); return rc; }

        rc = amisnap_backend_put(rw->be, key, encrypted.data, encrypted.len);
        amisnap_buf_free(&encrypted);
    } else {
        rc = amisnap_backend_put(rw->be, key, manifest_bytes.data, manifest_bytes.len);
        amisnap_buf_free(&manifest_bytes);
    }
    if (rc != AMISNAP_OK) return rc;

    memcpy(snapid_out, snapid, 17);
    return AMISNAP_OK;
}

typedef struct {
    void (*cb)(void *user, const char *snapid);
    void *user;
} list_ctx;

static void list_trampoline(void *user, const char *name)
{
    list_ctx *lc = (list_ctx *)user;
    size_t len = strlen(name);
    char snapid[17];

    if (len != 19 || strcmp(name + 16, ".mf") != 0)
        return; /* not "<16 hex>.mf" -- skip, per the documented lenient policy */

    memcpy(snapid, name, 16);
    snapid[16] = '\0';
    lc->cb(lc->user, snapid);
}

int amisnap_repo_list_snapshots(amisnap_backend *be,
                                 void (*cb)(void *user, const char *snapid), void *user)
{
    list_ctx lc;
    lc.cb = cb;
    lc.user = user;
    return amisnap_backend_list(be, "snapshots", list_trampoline, &lc);
}

int amisnap_repo_fetch_object(amisnap_backend *repo, const amisnap_repo_subkeys *subkeys,
                               uint8_t objcomp, const amisnap_content_ref *ref,
                               amisnap_buf *out)
{
    char key[AMISNAP_OBJECT_KEY_LEN];
    amisnap_buf raw;
    uint8_t actual_hash[32];
    int framed = (objcomp == AMISNAP_OBJCOMP_FRAMED);
    int rc;

    amisnap_repo_object_key(ref->hash, key);
    rc = amisnap_backend_get(repo, key, &raw);
    if (rc != AMISNAP_OK) return rc;

    if (!subkeys) {
        if (framed) {
            amisnap_buf content;

            rc = amisnap_frame_decode(raw.data, raw.len, ref->size, &content);
            amisnap_buf_free(&raw);
            if (rc != AMISNAP_OK) return rc;
            raw = content; /* take over: hash-check the decoded content below */
        } else if (raw.len != ref->size) {
            amisnap_buf_free(&raw);
            return AMISNAP_ERR_MALFORMED;
        }
        amisnap_blake2s256(raw.data, raw.len, actual_hash);
        if (memcmp(actual_hash, ref->hash, 32) != 0) {
            amisnap_buf_free(&raw);
            return AMISNAP_ERR_HASH_MISMATCH;
        }
        *out = raw; /* transfer ownership */
        return AMISNAP_OK;
    }

    {
        /* Encrypted: the plaintext inside the envelope is the raw
         * content (RAW) or the compression frame (FRAMED) -- a framed
         * body's stored size is only bounded, not predictable (the
         * store-raw fallback caps it at frame header + content). */
        size_t overhead = AMISNAP_REPO_NONCE_SIZE + AMISNAP_REPO_MAC_SIZE;
        size_t bodylen;
        uint8_t *body;

        if (framed) {
            if (raw.len < overhead + AMISNAP_FRAME_HDR_SIZE ||
                raw.len > overhead + AMISNAP_FRAME_HDR_SIZE + ref->size) {
                amisnap_buf_free(&raw);
                return AMISNAP_ERR_MALFORMED;
            }
        } else if (raw.len != overhead + ref->size) {
            amisnap_buf_free(&raw);
            return AMISNAP_ERR_MALFORMED;
        }
        bodylen = raw.len - overhead;

        body = (uint8_t *)malloc(bodylen ? bodylen : 1);
        if (!body) { amisnap_buf_free(&raw); return AMISNAP_ERR_NOMEM; }

        rc = amisnap_repo_decrypt_frame(subkeys, raw.data, raw.len, body);
        amisnap_buf_free(&raw);
        if (rc != AMISNAP_OK) { free(body); return rc; }

        if (framed) {
            amisnap_buf content;

            rc = amisnap_frame_decode(body, bodylen, ref->size, &content);
            free(body);
            if (rc != AMISNAP_OK) return rc;
            body = content.data;
        }

        amisnap_blake2s256(body, ref->size, actual_hash);
        if (memcmp(actual_hash, ref->hash, 32) != 0) { free(body); return AMISNAP_ERR_HASH_MISMATCH; }

        out->data = body;
        out->len = ref->size;
        out->cap = ref->size;
        return AMISNAP_OK;
    }
}

int amisnap_repo_open_manifest(const amisnap_repo_subkeys *subkeys, const char *snapid,
                                const uint8_t *raw, size_t rawlen, amisnap_buf *plaintext_out)
{
    uint16_t flags;
    size_t body_start;
    int rc;

    rc = amisnap_read_header(raw, rawlen, AMISNAP_FTYPE_MANIFEST, &flags, &body_start);
    if (rc != AMISNAP_OK) return rc;

    if ((flags & 1u) == 0) {
        /* Plaintext manifest. If this repository is encrypted (the
         * caller holds subkeys, i.e. the repo header said CIPHER 1 and
         * the passphrase verified), a plaintext manifest is NOT
         * acceptable -- it carries no MAC, so its only integrity is the
         * self-recomputable END_HASH, which an attacker with write
         * access to the destination (the exact threat encryption
         * exists for: an S3 bucket, an SMB share) can forge. Accepting
         * it would let a forged manifest reference existing objects
         * under attacker-chosen paths/protection bits, and verify/
         * restore would faithfully apply it -- a silent authentication
         * downgrade. Fail closed per "trust is everything": an
         * encrypted repository's manifests must be encrypted. Only a
         * genuinely plain (CIPHER 0) repository -- no subkeys -- may
         * return an unauthenticated manifest. */
        if (subkeys) return AMISNAP_ERR_MISSING_FIELD;
        amisnap_buf_init(plaintext_out);
        return amisnap_buf_bytes(plaintext_out, raw, rawlen);
    }
    if (!subkeys) return AMISNAP_ERR_MISSING_FIELD;

    {
        size_t framelen = rawlen - body_start;
        size_t plainlen;
        uint8_t *plain;
        uint8_t expect_nonce[AMISNAP_REPO_NONCE_SIZE];

        if (framelen < AMISNAP_REPO_NONCE_SIZE + AMISNAP_REPO_MAC_SIZE) return AMISNAP_ERR_MALFORMED;
        plainlen = framelen - AMISNAP_REPO_NONCE_SIZE - AMISNAP_REPO_MAC_SIZE;

        /* format.md's nonce discipline ties the manifest nonce
         * deterministically to its own snapid -- a mismatch here means
         * this manifest wasn't produced the way this repository's own
         * writer produces them (protocol violation, not just a MAC
         * failure the decrypt below would already have caught on its
         * own since the MAC covers the nonce too). */
        amisnap_repo_manifest_nonce(subkeys->nonce, (const uint8_t *)snapid, 16, expect_nonce);
        if (memcmp(raw + body_start, expect_nonce, AMISNAP_REPO_NONCE_SIZE) != 0)
            return AMISNAP_ERR_MALFORMED;

        plain = (uint8_t *)malloc(plainlen ? plainlen : 1);
        if (!plain) return AMISNAP_ERR_NOMEM;

        rc = amisnap_repo_decrypt_frame(subkeys, raw + body_start, framelen, plain);
        if (rc != AMISNAP_OK) { free(plain); return rc; }

        amisnap_buf_init(plaintext_out);
        rc = amisnap_write_header(plaintext_out, AMISNAP_FTYPE_MANIFEST, 0);
        if (rc == AMISNAP_OK)
            rc = amisnap_buf_bytes(plaintext_out, plain, plainlen);
        free(plain);
        if (rc != AMISNAP_OK) { amisnap_buf_free(plaintext_out); return rc; }
        return AMISNAP_OK;
    }
}

typedef struct {
    amisnap_backend *repo;
    const amisnap_repo_subkeys *subkeys;
    uint8_t objcomp;
    int full;
    amisnap_verify_result *result;
} verify_ctx;

static int verify_on_entry(void *user, const amisnap_entry_meta *entry)
{
    verify_ctx *vc = (verify_ctx *)user;
    size_t i;

    for (i = 0; i < entry->content_count; i++) {
        char key[AMISNAP_OBJECT_KEY_LEN];
        int exists;

        amisnap_repo_object_key(entry->content[i].hash, key);
        vc->result->objects_checked++;

        if (!vc->full) {
            exists = amisnap_backend_exists(vc->repo, key);
            if (exists <= 0) vc->result->objects_missing++;
            continue;
        }

        {
            amisnap_buf plain;
            int rc = amisnap_repo_fetch_object(vc->repo, vc->subkeys, vc->objcomp,
                                               &entry->content[i], &plain);

            if (rc == AMISNAP_ERR_NOT_FOUND) {
                vc->result->objects_missing++;
                continue;
            }
            if (rc != AMISNAP_OK) {
                /* Treat any other error (backend I/O, size mismatch,
                 * hash/MAC mismatch) the same as corrupt -- verify's
                 * job is to report, not to propagate a failure mid-scan
                 * and abandon the rest of the check. */
                vc->result->objects_corrupt++;
                continue;
            }
            amisnap_buf_free(&plain);
        }
    }
    return 0; /* verify deliberately never aborts early -- see amisnap_verify_manifest's doc comment */
}

int amisnap_verify_manifest(amisnap_backend *repo, const amisnap_repo_subkeys *subkeys,
                             uint8_t objcomp, const char *snapid,
                             const uint8_t *manifest_data, size_t manifest_len,
                             int full, amisnap_verify_result *result)
{
    verify_ctx vc;
    amisnap_manifest_visitor v;
    amisnap_buf plaintext;
    int rc;

    memset(result, 0, sizeof(*result));

    rc = amisnap_repo_open_manifest(subkeys, snapid, manifest_data, manifest_len, &plaintext);
    if (rc != AMISNAP_OK) return rc;

    vc.repo = repo;
    vc.subkeys = subkeys;
    vc.objcomp = objcomp;
    vc.full = full;
    vc.result = result;

    memset(&v, 0, sizeof(v));
    v.user = &vc;
    v.on_entry = verify_on_entry;

    rc = amisnap_manifest_decode(plaintext.data, plaintext.len, &v);
    amisnap_buf_free(&plaintext);
    return rc;
}
