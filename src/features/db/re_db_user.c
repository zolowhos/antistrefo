// re_db_user.c - the USER section: the reader's renames, kept at the tail of the .asdb.
// Module: feature (C11).
// Owns: the USER payload encoding, its load, and the in-place rewrite of the tail.
// Depends: re_db_priv.h, re_alt, re_crc, re_fsave. A torn rewrite fails its CRC.
#include "features/db/re_db_priv.h"

#include "utils/algo/re_crc.h"

#include <string.h>

// Payload: magic, CRC-32 of the entries, entry count, entry bytes, then the entries.
// Entry: u32 rva, u16 name length, the name. The CRC is what makes an in-place
// rewrite safe: a crash halfway leaves a payload whose CRC fails, which loads as no
// renames with a warning rather than as half of them.
#define RE_DB_USER_HDR 16u

void re_db_user_encode(const re_alt_t *m, re_strbuf_t *sb) {
    uint8_t h[RE_DB_USER_HDR];
    size_t base;
    size_t n = m ? RE_VEC_LEN(&m->ents) : 0u;
    re_crc_init();
    memset(h, 0, sizeof(h));
    base = sb->len;
    re_strbuf_append(sb, h, sizeof(h));
    for (size_t i = 0; i < n; i++) {
        const re_alt_ent_t *e = RE_VEC_PTR(&m->ents, re_alt_ent_t, i);
        uint8_t r[6];
        uint16_t len = (uint16_t)(e->name.n > 0xFFFFu ? 0xFFFFu : e->name.n);
        re_wr32(r, e->rva);
        re_wr16(r + 4, len);
        re_strbuf_append(sb, r, sizeof(r));
        re_strbuf_append(sb, e->name.p, len);
    }
    if (!sb->p || sb->len < base + RE_DB_USER_HDR)
        return;
    re_wr32((uint8_t *)sb->p + base, RE_DB_USER_MAGIC);
    re_wr32((uint8_t *)sb->p + base + 4,
            re_crc32_ieee_final(sb->p + base + RE_DB_USER_HDR,
                                (size_t)(sb->len - base - RE_DB_USER_HDR)));
    re_wr32((uint8_t *)sb->p + base + 8, (uint32_t)n);
    re_wr32((uint8_t *)sb->p + base + 12, (uint32_t)(sb->len - base - RE_DB_USER_HDR));
}

static bool parse_entries(re_span_t body, uint32_t count, re_alt_t *m) {
    uint64_t at = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t rva = 0;
        uint16_t len = 0;
        re_span_t name;
        if (!re_rd32(body, at, &rva) || !re_rd16(body, at + 4u, &len) ||
            !re_rd(body, at + 6u, len, &name))
            return false;
        if (!re_alt_set(m, rva, re_strn((const char *)name.p, len)))
            return false;
        at += 6u + (uint64_t)len;
    }
    return at == body.n;
}

bool re_db_user_load(const re_db_t *db, re_alt_t *m, bool *bad) {
    re_span_t h;
    re_span_t body;
    uint32_t bytes;
    *bad = false;
    if (!db || !db->ok || !db->user_off)
        return true;
    if (!re_rd(db->file.whole, db->user_off, RE_DB_USER_HDR, &h) ||
        re_db_f32(h, 0) != RE_DB_USER_MAGIC) {
        *bad = true;
        return true;
    }
    bytes = re_db_f32(h, 12);
    re_crc_init();
    if (!re_rd(db->file.whole, db->user_off + RE_DB_USER_HDR, bytes, &body) ||
        re_crc32_ieee_final(body.p, (size_t)body.n) != re_db_f32(h, 4) ||
        !parse_entries(body, re_db_f32(h, 8), m)) {
        *bad = true; // a torn rewrite; the renames before it are not trusted either
        re_vec_clear(&m->ents);
    }
    return true;
}

// The tail's offset, read from the header of the file as it is on disk now.
static bool user_offset(const char *path, re_arena_t *a, uint64_t *off) {
    re_file_t f;
    uint32_t magic = 0;
    uint32_t ver = 0;
    bool ok;
    if (re_file_open(path, a, &f) != RE_OK)
        return false;
    ok = re_rd32(f.whole, 0, &magic) && re_rd32(f.whole, 4, &ver) && re_rd64(f.whole, 80, off) &&
         magic == RE_DB_MAGIC && ver == RE_DB_VERSION && *off >= RE_DB_HDR && *off <= f.whole.n;
    re_file_close(&f);
    return ok;
}

bool re_db_user_save(const char *path, const re_alt_t *m, re_arena_t *scratch) {
    re_strbuf_t sb;
    uint64_t off = 0;
    if (!path || !user_offset(path, scratch, &off))
        return false;
    re_strbuf_init(&sb, scratch);
    re_db_user_encode(m, &sb);
    return sb.p && re_fsave_patch(path, off, sb.p, sb.len);
}
