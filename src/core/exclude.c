/* exclude.c -- see exclude.h. */
#include <stdlib.h>
#include <string.h>

#include "exclude.h"
#include "tlv.h" /* AMISNAP_OK / AMISNAP_ERR_NOMEM */

static int exclude_push(amisnap_exclude_list *out, const char *text, size_t len, int dir_only,
                         int anchored)
{
    if (out->count == out->cap) {
        size_t new_cap = out->cap == 0 ? 8 : out->cap * 2;
        amisnap_exclude_pattern *grown =
            (amisnap_exclude_pattern *)realloc(out->patterns, new_cap * sizeof(*grown));
        if (!grown)
            return AMISNAP_ERR_NOMEM;
        out->patterns = grown;
        out->cap = new_cap;
    }
    out->patterns[out->count].text = text;
    out->patterns[out->count].len = len;
    out->patterns[out->count].dir_only = dir_only;
    out->patterns[out->count].anchored = anchored;
    out->count++;
    return AMISNAP_OK;
}

int amisnap_exclude_parse(const char *text, size_t len, amisnap_exclude_list *out)
{
    char *p, *end;

    memset(out, 0, sizeof(*out));
    if (len == 0)
        return AMISNAP_OK;

    out->raw = (char *)malloc(len + 1);
    if (!out->raw)
        return AMISNAP_ERR_NOMEM;
    memcpy(out->raw, text, len);
    out->raw[len] = '\0';

    p = out->raw;
    end = out->raw + len;
    while (p < end) {
        char *line_start = p;
        char *nl = (char *)memchr(p, '\n', (size_t)(end - p));
        char *line_end = nl ? nl : end;
        char *ls = line_start, *le = line_end;
        int dir_only = 0, anchored = 0;
        char *scan;
        int rc;

        p = nl ? nl + 1 : end;

        if (le > ls && le[-1] == '\r')
            le--;
        while (ls < le && (*ls == ' ' || *ls == '\t'))
            ls++;
        while (le > ls && (le[-1] == ' ' || le[-1] == '\t'))
            le--;

        if (ls >= le || *ls == '#')
            continue; /* blank line or comment */

        if (le > ls && le[-1] == '/') {
            dir_only = 1;
            le--;
        }
        if (ls >= le)
            continue; /* pattern was just "/" -- nothing to match */

        if (*ls == '/') {
            anchored = 1;
            ls++;
        }
        for (scan = ls; scan < le; scan++) {
            if (*scan == '/') {
                anchored = 1;
                break;
            }
        }
        if (ls >= le)
            continue; /* pattern was just "/" with a trailing '/' too */

        *le = '\0'; /* safe: within out->raw's own allocation, never read past by a later line */

        rc = exclude_push(out, ls, (size_t)(le - ls), dir_only, anchored);
        if (rc != AMISNAP_OK) {
            amisnap_exclude_free(out);
            return rc;
        }
    }
    return AMISNAP_OK;
}

void amisnap_exclude_free(amisnap_exclude_list *list)
{
    if (!list)
        return;
    free(list->patterns);
    free(list->raw);
    list->patterns = NULL;
    list->raw = NULL;
    list->count = list->cap = 0;
}

static int ci_eq(char a, char b)
{
    if (a >= 'a' && a <= 'z')
        a = (char)(a - 'a' + 'A');
    if (b >= 'a' && b <= 'z')
        b = (char)(b - 'a' + 'A');
    return a == b;
}

/* Classic '*'/'?' wildcard match, single component (no '/' handling --
 * callers split on '/' first). Iterative backtracking, not recursive:
 * a hostile/very long pattern or path never risks stack depth here. */
static int glob_match_one(const char *pat, size_t plen, const char *s, size_t slen)
{
    size_t pi = 0, si = 0;
    size_t star_pi = (size_t)-1, star_si = 0;

    while (si < slen) {
        if (pi < plen && (pat[pi] == '?' || ci_eq(pat[pi], s[si]))) {
            pi++;
            si++;
        } else if (pi < plen && pat[pi] == '*') {
            star_pi = pi++;
            star_si = si;
        } else if (star_pi != (size_t)-1) {
            pi = star_pi + 1;
            si = ++star_si;
        } else {
            return 0;
        }
    }
    while (pi < plen && pat[pi] == '*')
        pi++;
    return pi == plen;
}

/* Finds the next '/'-delimited component starting at `*pos` (which may
 * be `len`, the end); returns its bounds and advances `*pos` past the
 * separator (or to `len` if this was the last component). */
static void next_component(const char *s, size_t len, size_t *pos, size_t *comp_start,
                            size_t *comp_len)
{
    size_t start = *pos;
    size_t i = start;
    while (i < len && s[i] != '/')
        i++;
    *comp_start = start;
    *comp_len = i - start;
    *pos = (i < len) ? i + 1 : len;
}

static int component_count(const char *s, size_t len)
{
    int n = 1;
    size_t i;
    for (i = 0; i < len; i++) {
        if (s[i] == '/')
            n++;
    }
    return n;
}

static int pattern_matches_anchored(const amisnap_exclude_pattern *pat, const char *path,
                                     size_t path_len)
{
    size_t ppos = 0, spos = 0;

    if (component_count(pat->text, pat->len) != component_count(path, path_len))
        return 0;

    while (ppos < pat->len || spos < path_len) {
        size_t pc_start, pc_len, sc_start, sc_len;

        next_component(pat->text, pat->len, &ppos, &pc_start, &pc_len);
        next_component(path, path_len, &spos, &sc_start, &sc_len);
        if (!glob_match_one(pat->text + pc_start, pc_len, path + sc_start, sc_len))
            return 0;
    }
    return 1;
}

static int pattern_matches_any_component(const amisnap_exclude_pattern *pat, const char *path,
                                          size_t path_len)
{
    size_t spos = 0;

    if (path_len == 0)
        return 0;

    while (spos < path_len) {
        size_t sc_start, sc_len;

        next_component(path, path_len, &spos, &sc_start, &sc_len);
        if (glob_match_one(pat->text, pat->len, path + sc_start, sc_len))
            return 1;
    }
    return 0;
}

int amisnap_exclude_match(const amisnap_exclude_list *list, const char *path, size_t path_len,
                           int is_dir)
{
    size_t i;

    if (!list)
        return 0;

    for (i = 0; i < list->count; i++) {
        const amisnap_exclude_pattern *pat = &list->patterns[i];

        if (pat->dir_only && !is_dir)
            continue;

        if (pat->anchored) {
            if (pattern_matches_anchored(pat, path, path_len))
                return 1;
        } else {
            if (pattern_matches_any_component(pat, path, path_len))
                return 1;
        }
    }
    return 0;
}
