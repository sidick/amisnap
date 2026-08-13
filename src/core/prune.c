/* prune.c -- see prune.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manifest.h"
#include "prune.h"
#include "repo.h"

#define SNAPID_KEY_LEN 32   /* "snapshots/" + 16 + ".mf" + NUL, generous */

/* A growable, sortable set of lowercase-hex object-hash strings (64
 * chars + NUL each) -- the "mark" set. Comparing filenames as hex
 * strings sidesteps writing a hex decoder: every object's on-disk name
 * already *is* its hash in this exact format (repo.c's own
 * amisnap_repo_object_key), so string equality is hash equality. */
typedef struct {
    char (*hashes)[65];
    size_t count, cap;
} hashset;

static const char HEXD[] = "0123456789abcdef";

static int hashset_add(hashset *hs, const uint8_t hash[32])
{
    size_t i;

    if (hs->count == hs->cap) {
        size_t newcap = hs->cap ? hs->cap * 2 : 256;
        char (*newarr)[65] = (char (*)[65])realloc(hs->hashes, newcap * sizeof(*newarr));
        if (!newarr) return AMISNAP_ERR_NOMEM;
        hs->hashes = newarr;
        hs->cap = newcap;
    }
    for (i = 0; i < 32; i++) {
        hs->hashes[hs->count][i * 2]     = HEXD[hash[i] >> 4];
        hs->hashes[hs->count][i * 2 + 1] = HEXD[hash[i] & 0x0Fu];
    }
    hs->hashes[hs->count][64] = '\0';
    hs->count++;
    return AMISNAP_OK;
}

static int hexcmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int hashset_contains(const hashset *hs, const char *hex64)
{
    return bsearch(hex64, hs->hashes, hs->count, sizeof(*hs->hashes), hexcmp) != NULL;
}

/* --- mark: decode every surviving manifest, collect every E_CONTENT
 * hash it references. --- */

typedef struct {
    hashset *hs;
    int status;
} mark_ctx;

static int mark_on_entry(void *user, const amisnap_entry_meta *entry)
{
    mark_ctx *mc = (mark_ctx *)user;
    size_t i;

    for (i = 0; i < entry->content_count; i++) {
        int rc = hashset_add(mc->hs, entry->content[i].hash);
        if (rc != AMISNAP_OK) { mc->status = rc; return rc; }
    }
    return 0;
}

typedef struct {
    amisnap_backend *repo;
    const amisnap_repo_subkeys *subkeys;
    hashset *hs;
    int status;
} mark_snap_ctx;

static void mark_snap_cb(void *user, const char *snapid)
{
    mark_snap_ctx *msc = (mark_snap_ctx *)user;
    char key[SNAPID_KEY_LEN];
    amisnap_buf mf, plaintext;
    amisnap_manifest_visitor v;
    mark_ctx mc;
    int rc;

    if (msc->status != AMISNAP_OK)
        return; /* already failed elsewhere in this pass -- stop doing work */

    snprintf(key, sizeof(key), "snapshots/%s.mf", snapid);
    rc = amisnap_backend_get(msc->repo, key, &mf);
    if (rc != AMISNAP_OK) { msc->status = rc; return; }

    rc = amisnap_repo_open_manifest(msc->subkeys, snapid, mf.data, mf.len, &plaintext);
    amisnap_buf_free(&mf);
    if (rc != AMISNAP_OK) { msc->status = rc; return; }

    mc.hs = msc->hs;
    mc.status = AMISNAP_OK;
    memset(&v, 0, sizeof(v));
    v.user = &mc;
    v.on_entry = mark_on_entry;

    rc = amisnap_manifest_decode(plaintext.data, plaintext.len, &v);
    amisnap_buf_free(&plaintext);
    if (rc != AMISNAP_OK) msc->status = rc;
}

/* --- sweep: objects/<hh>/<hex64> not in the mark set, then all of
 * tmp/ (nothing legitimately persists there between normally-completed
 * operations -- format.md's own commit protocol). --- */

typedef struct {
    amisnap_backend *repo;
    char bucket[3];
    const hashset *hs;
    amisnap_prune_result *result;
    int status;
} sweep_obj_ctx;

static void sweep_obj_cb(void *user, const char *name)
{
    sweep_obj_ctx *soc = (sweep_obj_ctx *)user;
    char key[AMISNAP_OBJECT_KEY_LEN];
    int rc;

    if (soc->status != AMISNAP_OK) return;
    if (hashset_contains(soc->hs, name)) return; /* still referenced -- keep */

    snprintf(key, sizeof(key), "objects/%s/%s", soc->bucket, name);
    rc = amisnap_backend_remove(soc->repo, key);
    if (rc == AMISNAP_OK) soc->result->objects_deleted++;
    else if (rc != AMISNAP_ERR_NOT_FOUND) soc->status = rc;
}

typedef struct {
    amisnap_backend *repo;
    const hashset *hs;
    amisnap_prune_result *result;
    int status;
} sweep_bucket_ctx;

static void sweep_bucket_cb(void *user, const char *name)
{
    sweep_bucket_ctx *sbc = (sweep_bucket_ctx *)user;
    char prefix[16];
    sweep_obj_ctx soc;
    int rc;

    if (sbc->status != AMISNAP_OK) return;
    if (strlen(name) != 2) return; /* not a real fan-out bucket -- ignore, not an error */

    snprintf(prefix, sizeof(prefix), "objects/%s", name);

    soc.repo = sbc->repo;
    memcpy(soc.bucket, name, 2);
    soc.bucket[2] = '\0';
    soc.hs = sbc->hs;
    soc.result = sbc->result;
    soc.status = AMISNAP_OK;

    rc = amisnap_backend_list(sbc->repo, prefix, sweep_obj_cb, &soc);
    if (rc != AMISNAP_OK) { sbc->status = rc; return; }
    if (soc.status != AMISNAP_OK) sbc->status = soc.status;
}

typedef struct {
    amisnap_backend *repo;
    amisnap_prune_result *result;
    int status;
} sweep_tmp_ctx;

static void sweep_tmp_cb(void *user, const char *name)
{
    sweep_tmp_ctx *stc = (sweep_tmp_ctx *)user;
    char key[280]; /* "tmp/" + longest legal name (a snapid.mf or hex64) */
    int rc;

    if (stc->status != AMISNAP_OK) return;

    snprintf(key, sizeof(key), "tmp/%s", name);
    rc = amisnap_backend_remove(stc->repo, key);
    if (rc == AMISNAP_OK) stc->result->tmp_deleted++;
    else if (rc != AMISNAP_ERR_NOT_FOUND) stc->status = rc;
}

int amisnap_prune_execute(amisnap_backend *repo, const amisnap_repo_subkeys *subkeys,
                           const char *const *delete_snapids,
                           size_t delete_count, amisnap_prune_result *result)
{
    size_t i;
    int rc;
    hashset hs;
    mark_snap_ctx msc;
    sweep_bucket_ctx sbc;
    sweep_tmp_ctx stc;

    memset(result, 0, sizeof(*result));

    /* Step 1 (format.md "Prune"): delete target manifests -- always
     * manifest-first, before anything below ever touches objects/. */
    for (i = 0; i < delete_count; i++) {
        char key[SNAPID_KEY_LEN];
        snprintf(key, sizeof(key), "snapshots/%s.mf", delete_snapids[i]);
        rc = amisnap_backend_remove(repo, key);
        if (rc == AMISNAP_OK) result->snapshots_deleted++;
        else if (rc != AMISNAP_ERR_NOT_FOUND) return rc;
    }

    /* Step 2: mark. */
    memset(&hs, 0, sizeof(hs));
    msc.repo = repo;
    msc.subkeys = subkeys;
    msc.hs = &hs;
    msc.status = AMISNAP_OK;
    rc = amisnap_repo_list_snapshots(repo, mark_snap_cb, &msc);
    if (rc == AMISNAP_OK) rc = msc.status;
    if (rc != AMISNAP_OK) { free(hs.hashes); return rc; }

    qsort(hs.hashes, hs.count, sizeof(*hs.hashes), hexcmp);

    /* Step 3: sweep -- objects/ first, then tmp/ (order between these
     * two doesn't matter for correctness, only manifests-before-
     * objects does; tmp/ never appears in the mark set at all). */
    sbc.repo = repo;
    sbc.hs = &hs;
    sbc.result = result;
    sbc.status = AMISNAP_OK;
    rc = amisnap_backend_list(repo, "objects", sweep_bucket_cb, &sbc);
    free(hs.hashes);
    if (rc == AMISNAP_OK) rc = sbc.status;
    if (rc != AMISNAP_OK) return rc;

    stc.repo = repo;
    stc.result = result;
    stc.status = AMISNAP_OK;
    rc = amisnap_backend_list(repo, "tmp", sweep_tmp_cb, &stc);
    if (rc == AMISNAP_OK) rc = stc.status;
    return rc;
}
