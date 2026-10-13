// re_flirt.c - byte pattern library matching over the start of a function.
// Module: feature (C11).
// Owns: the compiler, the comparison, the first byte index, and the native loader.
// Depends: re_flirt.h. Patterns are compiled once and compared literally, and a
//           pattern that runs off the end of the code is a miss rather than a
//           partial hit.
#include "features/lib/re_flirt.h"

#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_hex.h"

// One byte of pattern text, as the two characters that spell it. Every kind the
// matcher understands is produced here and nowhere else, so a new kind cannot be
// half added: if it is not in this switch it cannot be compiled and cannot match.
static bool sig_pair(char hi, char lo, uint8_t *kind, uint8_t *want) {
    int h = re_hex_val(hi);
    int l = re_hex_val(lo);
    if (hi == '?' && lo == '?') {
        *kind = RE_SIGK_ANY;
        *want = 0;
        return true;
    }
    if (hi == '?' && l >= 0) {
        *kind = RE_SIGK_LO;
        *want = (uint8_t)l;
        return true;
    }
    if (lo == '?' && h >= 0) {
        *kind = RE_SIGK_HI;
        *want = (uint8_t)(h << 4);
        return true;
    }
    if (h >= 0 && l >= 0) {
        *kind = RE_SIGK_EXACT;
        *want = (uint8_t)((h << 4) | l);
        return true;
    }
    return false;
}

// Read one token from the front of p. Returns how many pattern bytes it contributes,
// 0 at the end of the text, and -1 for a token that is not well formed. The three
// cases are distinct because a token that quietly contributed nothing would shift
// every byte after it and match the wrong place.
static int sig_token(const char *p, size_t n, size_t *used, uint8_t *kind, uint8_t *want) {
    *used = 0;
    if (n == 0)
        return 0;
    if (p[0] == '@') { // a relative displacement: four bytes the pattern makes no claim about
        for (int i = 0; i < 4; i++) {
            kind[i] = RE_SIGK_ANY;
            want[i] = 0;
        }
        *used = 1;
        return 4;
    }
    if (p[0] == '!') {
        int h;
        int l;
        if (n < 3)
            return -1;
        h = re_hex_val(p[1]);
        l = re_hex_val(p[2]);
        if (h < 0 || l < 0)
            return -1;
        kind[0] = RE_SIGK_NOT;
        want[0] = (uint8_t)((h << 4) | l);
        *used = 3;
        return 1;
    }
    if (n < 2 || !sig_pair(p[0], p[1], &kind[0], &want[0]))
        return -1;
    *used = 2;
    return 1;
}

static bool sig_append(re_sig_t *sig, size_t *out, const uint8_t *k, const uint8_t *w, size_t got) {
    if (*out + got > RE_SIG_MAX)
        return false;
    for (size_t i = 0; i < got; i++) {
        sig->kind[*out] = k[i];
        sig->want[*out] = w[i];
        (*out)++;
    }
    return true;
}

bool re_sig_compile(re_sig_t *sig) {
    size_t i = 0;
    size_t out = 0;
    if (!sig)
        return false;
    sig->n = 0;
    while (i < sig->pattern.n) {
        uint8_t k[4];
        uint8_t w[4];
        size_t used = 0;
        int got;
        if (sig->pattern.p[i] == ' ' || sig->pattern.p[i] == '\t') {
            i++;
            continue;
        }
        got = sig_token(sig->pattern.p + i, sig->pattern.n - i, &used, k, w);
        if (got < 0 || used == 0 || !sig_append(sig, &out, k, w, (size_t)got))
            return false;
        i += used;
    }
    // A pattern that claims no bytes, or that leaves every one of them to slack, can
    // never match. Refusing is the honest answer: counted, it would report coverage
    // that cannot fire, which reads exactly like a database that found nothing.
    if (out == 0 || (size_t)sig->slack >= out)
        return false;
    sig->n = (uint16_t)out;
    return true;
}

bool re_sig_match(const re_code_t *c, uint64_t va, const re_sig_t *sig) {
    re_span_t b;
    size_t i = 0;
    size_t cmp;
    if (!c || !sig || sig->n == 0)
        return false;
    // Slack is how many trailing bytes the pattern makes no claim about, which is what
    // lets one pattern cover a prologue that ends in an adjustment of unknown size.
    cmp = (size_t)sig->n - (size_t)sig->slack;
    if (cmp == 0 || cmp > RE_SIG_MAX || !re_code_at(c, va, &b) || b.n < cmp)
        return false;
    while (i < cmp) {
        uint8_t v = b.p[i];
        uint8_t k = sig->kind[i];
        if (k == RE_SIGK_EXACT) {
            if (v != sig->want[i])
                return false;
        } else if (k == RE_SIGK_NOT) {
            if (v == sig->want[i])
                return false;
        } else if (k == RE_SIGK_HI) {
            if ((v & 0xF0u) != (uint8_t)(sig->want[i] & 0xF0u))
                return false;
        } else if (k == RE_SIGK_LO) {
            if ((v & 0x0Fu) != (uint8_t)(sig->want[i] & 0x0Fu))
                return false;
        }
        i++;
    }
    return true;
}

// The bucket a signature belongs to. Only an exact first byte can rule a function out
// before reading it, so everything else shares the last bucket, which every function
// consults.
static size_t sig_bucket(const re_sig_t *s) {
    if (s->n == 0 || s->kind[0] != RE_SIGK_EXACT)
        return 256u;
    return s->want[0];
}

void re_sigdb_build(re_arena_t *a, const re_vec_t *sigs, re_sigdb_t *out) {
    size_t n = sigs ? RE_VEC_LEN(sigs) : 0;
    size_t cur[257];
    out->sigs = n ? (const re_sig_t *)sigs->base : NULL;
    out->n = 0;
    out->order = NULL;
    for (size_t i = 0; i < 258; i++)
        out->off[i] = 0;
    if (n == 0)
        return;
    out->order = (const re_sig_t **)re_arena_alloc(a, n * sizeof(*out->order));
    if (!out->order)
        return;
    for (size_t i = 0; i < n; i++)
        out->off[sig_bucket(&out->sigs[i]) + 1]++;
    for (size_t b = 0; b < 257; b++)
        out->off[b + 1] += out->off[b];
    for (size_t b = 0; b < 257; b++)
        cur[b] = out->off[b];
    // Scattered into bucket order while keeping declaration order inside a bucket, so
    // the same set always answers with the same signature.
    for (size_t i = 0; i < n; i++) {
        size_t b = sig_bucket(&out->sigs[i]);
        out->order[cur[b]++] = &out->sigs[i];
    }
    out->n = n;
}

bool re_sigdb_name(const re_sigdb_t *db, const re_code_t *c, const re_func_t *f, re_str_t *name,
                   re_str_t *module) {
    re_span_t b;
    if (!db || !f || db->n == 0 || !db->order || !re_code_at(c, f->va, &b) || b.n == 0)
        return false;
    for (int pass = 0; pass < 2; pass++) {
        size_t k = pass == 0 ? (size_t)b.p[0] : 256u;
        for (size_t j = db->off[k]; j < db->off[k + 1]; j++) {
            const re_sig_t *s = db->order[j];
            if (!re_sig_match(c, f->va, s))
                continue;
            if (name)
                *name = s->name;
            if (module)
                *module = s->module;
            return true;
        }
    }
    return false;
}

// Structural idioms the compiler emits on every x64 build, then library functions
// recovered from a build whose every symbol address is stated in a linker map. An
// idiom is named for what it is rather than for a library it may have come from; a
// library entry exists only after its bytes were matched at the address the map
// named. Provenance, verification and the limits of each entry are in
// docs/flirt-signatures.md. Nothing here was written from memory.
static const char *const kBuiltIn[] = {
    // mov rax, [rip+__security_cookie]; sub rax, rbp; xor ebp, ebp
    "gs_cookie_init:msvc:488b05????????4883c8????33c5",
    // mov rcx, [rip+__security_cookie]; xor eax, eax
    "gs_cookie_read:msvc:488b0d????????33c0",
    // lea r11, [rip+disp] ; test r11, r11 ; je ...  the guard dispatch prologue
    "guard_dispatch_icall:msvc:4c8d1d????????4985ff7405",
    // The /GS failure check: compare rcx with the cookie, rotate and test the high
    // half, return when it is clear, otherwise jump to the failure report. Both the
    // cookie displacement and the jump target are link time, so both are open.
    "__security_check_cookie:vcrt:483b0d@751048c1c11066f7c1ffff7501c348c1c910e9@",
    // Win64 stack probe: reserves the page, reads gs:[0x10] as the stack limit and
    // touches each page in turn. Emitted for any frame over a page.
    ("__chkstk:vcrt:4883ec104c8914244c895c24084d33db4c8d5424184c2bd04d0f42d365"
     "4c8b1c2510000000"),
    // The x64 CRT string and memory primitives below are the implementations from
    // the static runtime of the toolchain that built this project. They are name
    // and address verified, and they are version specific on purpose: a signature
    // that claimed every CRT version would be a guess. A reader with a different
    // runtime loads that runtime's patterns as a file instead.
    "memcpy:vcrt:488bc14c8d15@4983f80f0f87@",
    "memset:vcrt:488bc14c8bc94c8d15@0fb6d249bb01010101010101014c0fafda66490f6ec34983f80f0f87@",
    "memcmp:vcrt:482bd14983f8087222f6c107741466908a013a0411752c48ffc149ffc8f6c10775ee",
    "strlen:vcrt:488bc148f7d948a907000000740f66908a1048ffc084d2745fa80775f349b8",
    "strcat:vcrt:4c8bd9f6c10774128a0184c00f849100000048ffc1f6c10775ee488b014c8bd049b9",
    "strcpy:vcrt:4c8bd9482bcaf6c207741f8a0288040a84c0740a48ffc2f6c20775efeb0c498bc3c3",
    "strcmp:vcrt:482bd1f6c10774140fb6013a040a754f48ffc184c07445f6c10775ec49bb",
};

// Copy a field into the arena. The copy is not optional: a line read out of a mapped
// file points into that mapping, and the mapping is released as soon as the file is
// closed, which would leave every loaded pattern pointing at unmapped memory.
static re_str_t field(re_arena_t *a, const char *p, size_t n) {
    re_str_t s = re_str_trim(re_strn(p, n));
    return re_strn(re_arena_strndup(a, s.p, s.n), s.n);
}

// The optional slack field, which is how many trailing bytes the pattern makes no
// claim about. Absent is a slack of zero.
static bool sig_slack(re_arena_t *a, re_str_t t, long sep3, uint8_t *out) {
    re_str_t sv;
    unsigned v = 0;
    if (sep3 < 0)
        return true;
    sv = field(a, t.p + sep3 + 1, t.n - (size_t)sep3 - 1u);
    if (sv.n == 0 || sv.n > 3u)
        return false;
    for (size_t i = 0; i < sv.n; i++) {
        if (sv.p[i] < '0' || sv.p[i] > '9')
            return false;
        v = v * 10u + (unsigned)(sv.p[i] - '0');
    }
    if (v > 255u) // three digits can still be past what a byte holds
        return false;
    *out = (uint8_t)v;
    return true;
}

typedef enum {
    SIG_LINE_SKIP = 0, // blank or a comment: not a failure
    SIG_LINE_OK = 1,   // a signature that can match
    SIG_LINE_BAD = 2,  // a line that meant to be one and could not be
} sig_line_t;

// Three fields separated by colons, with a space allowed either side of each, and an
// optional fourth. The trimming is not decoration: the documented line puts a space
// around every colon, and without this the pattern arrives as " 488bc453", every
// signature in a valid file loads, is counted, and matches nothing.
static sig_line_t split_line(re_arena_t *a, re_str_t line, re_sig_t *out) {
    re_str_t t = re_str_trim(line);
    long sep1;
    long sep2;
    long sep3;
    size_t pend;
    if (t.n == 0 || t.p[0] == '#')
        return SIG_LINE_SKIP;
    sep1 = re_str_find_cstr(t, ":", 0);
    if (sep1 < 0)
        return SIG_LINE_BAD;
    sep2 = re_str_find_cstr(t, ":", (size_t)sep1 + 1u);
    if (sep2 < 0)
        return SIG_LINE_BAD;
    sep3 = re_str_find_cstr(t, ":", (size_t)sep2 + 1u);
    pend = sep3 < 0 ? t.n : (size_t)sep3;
    out->name = field(a, t.p, (size_t)sep1);
    out->module = field(a, t.p + sep1 + 1, (size_t)(sep2 - sep1 - 1));
    out->pattern = field(a, t.p + sep2 + 1, pend - (size_t)sep2 - 1u);
    out->slack = 0;
    out->crc = 0;
    out->has_crc = false;
    if (out->name.n == 0 || out->pattern.n == 0)
        return SIG_LINE_BAD;
    if (!sig_slack(a, t, sep3, &out->slack))
        return SIG_LINE_BAD;
    // Compiled here, so the number a load reports is the number that can match.
    return re_sig_compile(out) ? SIG_LINE_OK : SIG_LINE_BAD;
}

size_t re_flirt_builtin(re_arena_t *a, re_vec_t *out) {
    size_t before = RE_VEC_LEN(out);
    for (size_t i = 0; i < sizeof(kBuiltIn) / sizeof(kBuiltIn[0]); i++) {
        re_sig_t s;
        if (split_line(a, re_str(kBuiltIn[i]), &s) == SIG_LINE_OK)
            RE_VEC_PUSH(out, a, s);
    }
    return RE_VEC_LEN(out) - before;
}

// The line containing a byte, without its terminator. Both LF and CRLF are accepted,
// and a file with no final newline still yields its last line.
static re_str_t line_at(re_span_t f, uint64_t off) {
    uint64_t end = off;
    while (end < f.n && f.p[end] != '\n' && f.p[end] != '\r')
        end++;
    return re_strn((const char *)f.p + off, (size_t)(end - off));
}

size_t re_flirt_load_ex(re_arena_t *a, const char *path, re_vec_t *out,
                        re_flirt_load_stat_t *stat) {
    re_file_t f;
    uint64_t off = 0;
    size_t before = out ? RE_VEC_LEN(out) : 0;
    if (stat) {
        stat->before = before;
        stat->loaded = 0;
        stat->rejected = 0;
        stat->skipped = 0;
    }
    if (!out || re_file_open(path, a, &f) != RE_OK)
        return 0;
    while (off < f.whole.n) {
        re_str_t line = line_at(f.whole, off);
        re_sig_t s;
        sig_line_t kind = split_line(a, line, &s);
        if (kind == SIG_LINE_OK && RE_VEC_PUSH(out, a, s)) {
            if (stat)
                stat->loaded++;
        } else if (kind == SIG_LINE_BAD) {
            if (stat)
                stat->rejected++;
        } else if (kind == SIG_LINE_SKIP && stat) {
            stat->skipped++;
        }
        off += line.n;
        if (off < f.whole.n && f.whole.p[off] == '\r')
            off++;
        if (off < f.whole.n && f.whole.p[off] == '\n')
            off++;
    }
    re_file_close(&f);
    before = RE_VEC_LEN(out) - before;
    if (stat)
        stat->loaded = before;
    return before;
}

size_t re_flirt_load(re_arena_t *a, const char *path, re_vec_t *out) {
    return re_flirt_load_ex(a, path, out, NULL);
}

size_t re_flirt_name_all(const re_sigdb_t *db, re_code_t *code, re_fscan_t *scan) {
    size_t named = 0;
    if (!db || !code || !scan || db->n == 0)
        return 0;
    for (size_t i = 0; i < RE_VEC_LEN(&scan->funcs); i++) {
        re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, i);
        re_str_t nm = re_str("");
        re_str_t mod = re_str("");
        if (f->name.n) // the image states this one; a pattern only infers
            continue;
        if (!re_sigdb_name(db, code, f, &nm, &mod))
            continue;
        f->name = nm;
        f->flags |= RE_FUNC_FLIRT;
        named++;
    }
    return named;
}
