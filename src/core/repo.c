/* repo.c -- see repo.h. */
#include <stdio.h>
#include <string.h>

#include "blake2s.h"
#include "repo.h"

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

void amisnap_repo_writer_init(amisnap_repo_writer *rw, amisnap_backend *be)
{
    rw->be = be;
    amisnap_manifest_writer_init(&rw->mw);
    rw->snap_days = rw->snap_mins = rw->snap_ticks = 0;
    rw->have_snap = 0;
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

int amisnap_repo_writer_file(amisnap_repo_writer *rw, amisnap_entry_meta *entry,
                              const void *data, size_t len)
{
    uint8_t hash[32];
    amisnap_content_ref ref;
    char key[AMISNAP_OBJECT_KEY_LEN];
    int rc;

    if (entry->type != AMISNAP_ETYPE_FILE)
        return AMISNAP_ERR_MALFORMED;

    entry->has_size = 1;
    entry->size = len;

    if (len == 0) {
        entry->content = NULL;
        entry->content_count = 0;
        return amisnap_manifest_writer_entry(&rw->mw, entry);
    }

    amisnap_blake2s256(data, len, hash);
    amisnap_repo_object_key(hash, key);

    rc = amisnap_backend_exists(rw->be, key);
    if (rc < 0) return rc;
    if (rc == 0) {
        /* Object genuinely new: write it. rc == 1 (already present)
         * skips this entirely -- format.md "Objects already present
         * are never rewritten." */
        rc = amisnap_backend_put(rw->be, key, data, len);
        if (rc != AMISNAP_OK) return rc;
    }

    memcpy(ref.hash, hash, 32);
    ref.size = len;
    entry->content = &ref;
    entry->content_count = 1;

    return amisnap_manifest_writer_entry(&rw->mw, entry);
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

    rc = amisnap_backend_put(rw->be, key, manifest_bytes.data, manifest_bytes.len);
    amisnap_buf_free(&manifest_bytes);
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

typedef struct {
    amisnap_backend *repo;
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
            amisnap_buf obj;
            uint8_t actual_hash[32];
            int rc = amisnap_backend_get(vc->repo, key, &obj);

            if (rc == AMISNAP_ERR_NOT_FOUND) {
                vc->result->objects_missing++;
                continue;
            }
            if (rc != AMISNAP_OK) {
                /* Treat any other backend error the same as missing --
                 * verify's job is to report, not to propagate an I/O
                 * failure mid-scan and abandon the rest of the check. */
                vc->result->objects_missing++;
                continue;
            }

            if (obj.len != entry->content[i].size) {
                vc->result->objects_corrupt++;
                amisnap_buf_free(&obj);
                continue;
            }
            amisnap_blake2s256(obj.data, obj.len, actual_hash);
            if (memcmp(actual_hash, entry->content[i].hash, 32) != 0)
                vc->result->objects_corrupt++;
            amisnap_buf_free(&obj);
        }
    }
    return 0; /* verify deliberately never aborts early -- see amisnap_verify_manifest's doc comment */
}

int amisnap_verify_manifest(amisnap_backend *repo, const uint8_t *manifest_data, size_t manifest_len,
                             int full, amisnap_verify_result *result)
{
    verify_ctx vc;
    amisnap_manifest_visitor v;

    memset(result, 0, sizeof(*result));
    vc.repo = repo;
    vc.full = full;
    vc.result = result;

    memset(&v, 0, sizeof(v));
    v.user = &vc;
    v.on_entry = verify_on_entry;

    return amisnap_manifest_decode(manifest_data, manifest_len, &v);
}
