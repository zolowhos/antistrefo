// re_flatten.c - functions whose control flow a dispatcher loop drives.
// Module: feature (C11).
// Owns: re_deep_flatten and the dispatcher test.
// Depends: re_deep_priv.h, re_code. Flags and annotates; it never rewrites the flow.
#include "features/analysis/re_deep_priv.h"

// A flattened function is a loop whose one indirect branch is a computed jump fed by a
// state variable, with the rest of the body reaching back to it. The shape is counted
// rather than guessed: one indirect branch, and more than one edge back to the head.
static bool is_dispatcher(const re_analysis_t *an, const re_func_t *f, uint64_t *at) {
    size_t back = 0;
    bool indirect = false;
    if (f->n_insns < 8u || !(f->flags & RE_FUNC_JTABLE))
        return false;
    for (size_t i = 0; i < RE_VEC_LEN(&an->scan.edges); i++) {
        const re_edge_t *e = RE_VEC_PTR(&an->scan.edges, re_edge_t, i);
        if (e->from < f->va || e->from >= f->va + f->size)
            continue;
        if (!e->has_to && e->kind == RE_EDGE_JUMP) {
            if (indirect)
                return false; // two dispatches is a switch, not a state machine
            indirect = true;
            *at = e->from;
        }
        if (e->has_to && e->to == f->va && e->kind != RE_EDGE_DATA)
            back++;
    }
    return indirect && back >= 2u;
}

size_t re_deep_flatten(re_analysis_t *an) {
    size_t n = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&an->scan.funcs); i++) {
        re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, i);
        re_note_t note;
        uint64_t at = 0;
        if (!is_dispatcher(an, f, &at))
            continue;
        f->flags |= RE_FUNC_FLATTENED;
        note.va = f->va;
        note.aux = at;
        note.kind = RE_NOTE_FLATTENED;
        note.text = re_str("flattened dispatcher");
        RE_VEC_PUSH(&an->notes, an->arena, note);
        n++;
    }
    return n;
}
