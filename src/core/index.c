/* index.c -- see index.h. */
#include <stdlib.h>
#include <string.h>

#include "index.h"
#include "manifest.h"

typedef struct {
    amisnap_index *idx;
} build_ctx;

static int on_entry_cb(void *user, const amisnap_entry_meta *entry)
{
    build_ctx *bc = (build_ctx *)user;
    amisnap_entry_meta copy;
    amisnap_content_ref *refs = NULL;

    copy = *entry; /* path/comment/link still borrow into idx->raw, which
                     * outlives this entry -- only .content needs a real
                     * copy (manifest.h's decode scratch is reused per
                     * entry and would otherwise dangle). */

    if (entry->content_count > 0) {
        refs = (amisnap_content_ref *)malloc(entry->content_count * sizeof(*refs));
        if (!refs) return AMISNAP_ERR_NOMEM; /* abort decode immediately -- see manifest.h's visitor contract */
        memcpy(refs, entry->content, entry->content_count * sizeof(*refs));
    }
    copy.content = refs;

    if (bc->idx->count == bc->idx->cap) {
        size_t newcap = bc->idx->cap ? bc->idx->cap * 2 : 64;
        amisnap_entry_meta *newarr =
            (amisnap_entry_meta *)realloc(bc->idx->entries, newcap * sizeof(*newarr));
        if (!newarr) { free(refs); return AMISNAP_ERR_NOMEM; }
        bc->idx->entries = newarr;
        bc->idx->cap = newcap;
    }
    bc->idx->entries[bc->idx->count++] = copy;
    return 0;
}

static int path_cmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    size_t minlen = alen < blen ? alen : blen;
    int c = minlen ? memcmp(a, b, minlen) : 0;
    if (c != 0) return c;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

static int entry_path_cmp_qsort(const void *a, const void *b)
{
    const amisnap_entry_meta *ea = (const amisnap_entry_meta *)a;
    const amisnap_entry_meta *eb = (const amisnap_entry_meta *)b;
    return path_cmp(ea->path, ea->path_len, eb->path, eb->path_len);
}

int amisnap_index_build(const uint8_t *manifest_data, size_t manifest_len, amisnap_index *out)
{
    build_ctx bc;
    amisnap_manifest_visitor v;
    int rc;

    memset(out, 0, sizeof(*out));
    amisnap_buf_init(&out->raw);
    rc = amisnap_buf_bytes(&out->raw, manifest_data, manifest_len);
    if (rc != AMISNAP_OK) return rc;

    bc.idx = out;
    memset(&v, 0, sizeof(v));
    v.user = &bc;
    v.on_entry = on_entry_cb;

    rc = amisnap_manifest_decode(out->raw.data, out->raw.len, &v);
    if (rc != AMISNAP_OK) { amisnap_index_free(out); return rc; }

    /* Sorted by path so amisnap_index_lookup() can binary-search --
     * see that function's own comment for why this replaced a linear
     * scan (a real, measured problem, not a preemptive optimisation).
     * Every entry moves as a whole struct (its .content pointer moves
     * with it), so this doesn't disturb ownership at all. */
    qsort(out->entries, out->count, sizeof(*out->entries), entry_path_cmp_qsort);

    return AMISNAP_OK;
}

void amisnap_index_free(amisnap_index *idx)
{
    size_t i;

    for (i = 0; i < idx->count; i++)
        free((void *)idx->entries[i].content); /* the one place this module owns .content; cast away const deliberately */
    free(idx->entries);
    amisnap_buf_free(&idx->raw);
    idx->entries = NULL;
    idx->count = idx->cap = 0;
}

const amisnap_entry_meta *amisnap_index_lookup(const amisnap_index *idx,
                                                 const uint8_t *path, size_t path_len)
{
    size_t lo = 0, hi = idx->count;

    /* Binary search over amisnap_index_build()'s own sorted order.
     * Confirmed empirically (implementation-plan.md's real-FFS-era
     * archive-bit-wiring follow-up) that the previous O(n) linear scan
     * genuinely mattered at only 10k files: called once per scanned
     * file against an index of the same size, it made a "nothing
     * changed" snapshot slower than not having the fast path at all
     * (O(n^2) beats a real 10k-file --benchmark-until gate). */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = path_cmp(idx->entries[mid].path, idx->entries[mid].path_len, path, path_len);
        if (c == 0) return &idx->entries[mid];
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

int amisnap_index_unchanged(const amisnap_entry_meta *last, const amisnap_entry_meta *current)
{
    uint32_t last_prot, cur_prot;

    if (!last)
        return 0;

    if (last->type != current->type)
        return 0;

    if (!(current->prot & AMISNAP_FIBF_ARCHIVE))
        return 0;

    last_prot = last->prot & ~AMISNAP_FIBF_ARCHIVE;
    cur_prot  = current->prot & ~AMISNAP_FIBF_ARCHIVE;
    if (last_prot != cur_prot)
        return 0;

    if (last->date_days != current->date_days ||
        last->date_mins != current->date_mins ||
        last->date_ticks != current->date_ticks)
        return 0;

    if (last->has_comment != current->has_comment)
        return 0;
    if (last->has_comment &&
        (last->comment_len != current->comment_len ||
         memcmp(last->comment, current->comment, last->comment_len) != 0))
        return 0;

    if (last->has_owner != current->has_owner)
        return 0;
    if (last->has_owner && (last->uid != current->uid || last->gid != current->gid))
        return 0;

    switch (current->type) {
    case AMISNAP_ETYPE_FILE:
        if (last->has_size != current->has_size)
            return 0;
        if (last->has_size && last->size != current->size)
            return 0;
        break;
    case AMISNAP_ETYPE_SOFTLINK:
    case AMISNAP_ETYPE_HARDLINK:
        if (last->has_link != current->has_link)
            return 0;
        if (last->has_link &&
            (last->link_len != current->link_len ||
             memcmp(last->link, current->link, last->link_len) != 0))
            return 0;
        break;
    default:
        break;
    }

    return 1;
}
