// re_vm.c - functions a virtualiser protects, reported rather than decompiled.
// Module: feature (C11).
// Owns: re_deep_vm, the section signatures, and the VM entry and dispatcher tests.
// Depends: re_deep_priv.h, re_code. Detection only: no handler is ever lifted.
#include "features/analysis/re_deep_priv.h"

#include <string.h>

// Sections a known virtualiser owns. A function inside one is virtualised whatever
// its bytes look like, because those bytes are the handler table, not the program.
static const char *const kVmSec[] = {".vmp0", ".vmp1", ".themida", ".winlice"};

static bool sec_named(const re_pe_section_t *s, const char *name) {
    size_t n = 0;
    while (name[n])
        n++;
    return memcmp(s->name, name, n) == 0 && (s->name[n] == 0 || n >= sizeof(s->name));
}

static const re_pe_section_t *vm_section(const re_pe_t *pe, uint32_t rva) {
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        if (rva < s->vaddr || rva - s->vaddr >= s->vsize)
            continue;
        for (size_t k = 0; k < sizeof(kVmSec) / sizeof(kVmSec[0]); k++)
            if (sec_named(s, kVmSec[k]))
                return s;
    }
    return NULL;
}

// A VM entry saves every general register before it does anything else, which no
// ordinary prologue does. Ten pushes inside the first sixteen bytes is the shape.
static bool push_all(const re_code_t *c, uint64_t va) {
    uint64_t at = va;
    uint32_t pushes = 0;
    for (uint32_t i = 0; i < 12u && at < va + 48u; i++) {
        re_insn_t in;
        if (!re_code_insn(c, at, &in) || !in.size)
            break;
        if (in.insn_id >= 0x0050u && in.insn_id <= 0x0057u)
            pushes++;
        at += in.size;
    }
    return pushes >= 10u;
}

// A dispatcher is an indirect jump with far more targets than a switch has cases.
static bool big_dispatch(const re_analysis_t *an, const re_func_t *f) {
    size_t targets = 0;
    if (!(f->flags & RE_FUNC_JTABLE))
        return false;
    for (size_t i = 0; i < RE_VEC_LEN(&an->scan.edges); i++) {
        const re_edge_t *e = RE_VEC_PTR(&an->scan.edges, re_edge_t, i);
        if (e->from >= f->va && e->from < f->va + f->size && !e->has_to && e->kind == RE_EDGE_JUMP)
            targets++;
    }
    return targets >= 20u;
}

static void flag_vm(re_analysis_t *an, re_func_t *f, const char *why, uint64_t handlers) {
    re_note_t n;
    f->flags |= RE_FUNC_VIRTUALIZED;
    n.va = f->va;
    n.aux = handlers;
    n.kind = RE_NOTE_VM;
    n.text = re_str(why);
    RE_VEC_PUSH(&an->notes, an->arena, n);
}

size_t re_deep_vm(re_analysis_t *an) {
    size_t n = 0;
    for (uint16_t i = 0; i < an->pe.n_sec; i++) {
        re_note_t note;
        for (size_t k = 0; k < sizeof(kVmSec) / sizeof(kVmSec[0]); k++) {
            if (!sec_named(&an->pe.sec[i], kVmSec[k]))
                continue;
            note.va = an->code.base + an->pe.sec[i].vaddr;
            note.aux = an->pe.sec[i].vsize;
            note.kind = RE_NOTE_PACKER;
            note.text = re_str(kVmSec[k]);
            RE_VEC_PUSH(&an->notes, an->arena, note);
        }
    }
    for (size_t i = 0; i < RE_VEC_LEN(&an->scan.funcs); i++) {
        re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, i);
        const re_pe_section_t *s = vm_section(&an->pe, f->rva);
        if (s) {
            flag_vm(an, f, s->name, 0);
            n++;
        } else if (push_all(&an->code, f->va) || big_dispatch(an, f)) {
            flag_vm(an, f, "vm entry", 0);
            n++;
        }
    }
    return n;
}
