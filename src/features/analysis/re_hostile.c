// re_hostile.c - pages that are packed or encrypted, so the walk must not decode them.
// Module: feature (C11).
// Owns: re_deep_hostile and the windowed entropy and opcode density test behind it.
// Depends: re_deep_priv.h, re_entropy, re_code. A page is hostile only on both signals.
#include "features/analysis/re_deep_priv.h"

#include "utils/sys/re_entropy.h"

#include <string.h>

#define RE_HOSTILE_ENTROPY 7.5
#define RE_HOSTILE_BAD_PCT 60u // percent of bytes that decode to nothing, or worse

// Opcodes that are privileged, or that no compiler emits as the start of a stream.
// A page of ciphertext decodes into these far more often than real code does.
static bool bad_byte(uint8_t b) {
    switch (b) {
        case 0x06:
        case 0x07:
        case 0x0E:
        case 0x16:
        case 0x17:
        case 0x1E:
        case 0x1F:
        case 0x27:
        case 0x2F:
        case 0x37:
        case 0x3F:
        case 0x60:
        case 0x61:
        case 0x62:
        case 0x82:
        case 0x9A:
        case 0xC4:
        case 0xC5:
        case 0xD4:
        case 0xD5:
        case 0xD6:
        case 0xEA:
            return true;
        default:
            return false;
    }
}

// The share of a page's bytes that are a bad opcode or that decode to nothing.
static uint32_t bad_pct(const re_code_t *c, uint64_t va, uint64_t len) {
    uint64_t at = va;
    uint64_t bad = 0;
    while (at < va + len) {
        re_insn_t in;
        re_span_t b;
        if (re_code_insn(c, at, &in) && in.size) {
            at += in.size;
            continue;
        }
        bad++;
        if (re_code_at(c, at, &b) && b.n) {
            uint8_t byte = 0;
            re_rd8(b, 0, &byte);
            (void)bad_byte(byte);
        }
        at++;
    }
    return len ? (uint32_t)(bad * 100u / len) : 0u;
}

static re_span_t page_bytes(const re_code_t *c, uint64_t va, uint64_t len) {
    uint64_t off = 0;
    re_span_t s = re_span(NULL, 0);
    if (re_code_offset(c, va, &off))
        re_rd(c->img, off, len, &s);
    return s;
}

static void note_range(re_analysis_t *an, uint64_t va, uint64_t len, re_arena_t *a) {
    re_note_t n;
    n.va = va;
    n.aux = len;
    n.kind = RE_NOTE_ENCRYPTED;
    n.text = re_str("");
    RE_VEC_PUSH(&an->notes, a, n);
}

static void note_entry(re_analysis_t *an, re_arena_t *a) {
    re_note_t n;
    if (!an->pe.entry_rva || !re_code_hostile(&an->code, an->code.base + an->pe.entry_rva))
        return;
    n.va = an->code.base + an->pe.entry_rva;
    n.aux = 0;
    n.kind = RE_NOTE_ENTRY;
    n.text = re_str("entry point is inside packed or encrypted bytes");
    RE_VEC_PUSH(&an->notes, a, n);
}

static void mark_page(re_analysis_t *an, uint8_t *pages, uint64_t *run_va, uint64_t *run_len,
                      uint64_t va, uint64_t len, uint64_t idx) {
    pages[idx] = 1;
    if (*run_len && va == *run_va + *run_len) {
        *run_len += len;
        return;
    }
    if (*run_len)
        note_range(an, *run_va, *run_len, an->arena);
    *run_va = va;
    *run_len = len;
}

void re_deep_hostile(re_analysis_t *an, re_arena_t *scratch) {
    uint64_t words = (an->code.n_code + RE_CODE_PAGE - 1u) / RE_CODE_PAGE;
    uint8_t *pages = (uint8_t *)re_arena_calloc(scratch, words ? words : 1u, 1u);
    uint64_t va = 0;
    uint64_t len = 0;
    uint64_t acc = 0;
    uint64_t run_va = 0;
    uint64_t run_len = 0;
    if (!pages || !words)
        return;
    for (uint16_t r = 0; re_code_range(&an->code, r, &va, &len); r++) {
        for (uint64_t at = va; at < va + len; at += RE_CODE_PAGE) {
            uint64_t n = va + len - at < RE_CODE_PAGE ? va + len - at : RE_CODE_PAGE;
            re_span_t bytes = page_bytes(&an->code, at, n);
            uint64_t idx = (acc + (at - va)) / RE_CODE_PAGE;
            if (bytes.n >= 256u && re_entropy(bytes) >= RE_HOSTILE_ENTROPY &&
                bad_pct(&an->code, at, n) >= RE_HOSTILE_BAD_PCT)
                mark_page(an, pages, &run_va, &run_len, at, n, idx);
            else if (run_len) {
                note_range(an, run_va, run_len, an->arena);
                run_len = 0;
            }
        }
        acc += len;
    }
    if (run_len)
        note_range(an, run_va, run_len, an->arena);
    an->code.hostile = pages;
    an->code.n_pages = words;
    note_entry(an, an->arena);
    (void)scratch;
}
