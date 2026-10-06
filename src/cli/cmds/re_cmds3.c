// re_cmds3.c - the disassembly surface: functions, disassembly, and xrefs.
// Module: cli (C11).
// Owns: the funcs, disasm and xrefs commands, and the code map they share.
// Depends: re_code, re_func, re_xref, re_disasm. One JSON object on stdout.
#include "cli/cmds/re_cmds3.h"

#include "cli/render/re_render.h"
#include "cli/render/re_report.h"

#include "cli/cmds/re_prep.h"

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_jtable.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/lib/re_flirt.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/json/re_json.h"
#include "utils/text/re_strbuf.h"

// The flags a function carries, as names rather than a bitmask, because a caller
// reading this should not have to know which bit means prologue.
static void emit_flags(re_jw_t *w, uint32_t flags) {
    static const struct {
        uint32_t bit;
        const char *name;
    } kNames[] = {
        {RE_FUNC_ENTRY, "entry"},
        {RE_FUNC_EXPORT, "export"},
        {RE_FUNC_PROLOGUE, "prologue"},
        {RE_FUNC_FLIRT, "flirt"},
        {RE_FUNC_THUNK, "thunk"},
        {RE_FUNC_NORETURN, "noreturn"},
        {RE_FUNC_OVERLAP, "overlap"},
        {RE_FUNC_EXTERNAL, "calls_outside"},
        {RE_FUNC_JTABLE, "indirect_jump"},
        {RE_FUNC_RET, "returns"},
        // Provenance, so a reader can tell a bound the compiler stated from one
        // inferred from bytes. Only the first two are facts about the binary; the
        // rest are what a pass concluded, and a report should not hide which.
        {RE_FUNC_UNWIND, "unwind"},
        {RE_FUNC_JUNK, "junk"},
        {RE_FUNC_TRUNC, "trunc"},
    };
    re_jw_key(w, "flags");
    re_jw_arr(w);
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        if (flags & kNames[i].bit)
            re_jw_str(w, re_str(kNames[i].name));
    }
    re_jw_arr_end(w);
}

static void emit_func(re_ctx_t *ctx, re_code_t *code, re_jw_t *w, const re_func_t *f, size_t edges,
                      const re_xrefset_t *xs, const re_pe_t *pe) {
    re_stack_t st;
    re_jw_obj(w);
    re_jw_khex(w, "va", f->va, 16);
    re_jw_ku64(w, "rva", f->rva);
    re_jw_ku64(w, "size", f->size);
    re_jw_ku64(w, "insns", f->n_insns);
    re_jw_ku64(w, "frame", f->frame_size);
    re_jw_ku64(w, "calls", f->n_calls);
    re_jw_ku64(w, "jumps", f->n_jumps);
    re_jw_ku64(w, "out_edges", edges);
    // Bytes inside the body that do not decode. Emitted only when there are some,
    // because a zero here means nothing was skipped and a reader should be able to
    // tell that from a field that was never computed.
    if (f->junk)
        re_jw_ku64(w, "junk", f->junk);
    // Transfers whose destination could not be resolved: a call through a register
    // and a jump through a table both land here, and a reader counting calls needs
    // to know how many were left open rather than silently missing them.
    if (f->open_edges)
        re_jw_ku64(w, "open_edges", f->open_edges);
    if (f->flags & RE_FUNC_TRUNC)
        re_jw_kbool(w, "truncated", true);
    if (f->dispatch)
        re_jw_khex(w, "dispatch", f->dispatch, 16);
    re_stack_analyze(code, f, ctx->arena, &st);
    re_stack_apply_image(&st, pe);
    re_jw_kcstr(w, "cc", re_cc_name(st.cc));
    re_jw_ku64(w, "params", st.n_params);
    re_jw_ku64(w, "locals", st.n_locals);
    // The registers as well as the count. A count says how many arguments there are;
    // the names say which ones, which is what makes a recovered signature readable
    // without cross checking the calling convention by hand.
    re_jw_key(w, "arg_regs");
    re_jw_arr(w);
    for (uint32_t k = 0; k < st.n_params && k < RE_CC_MAX_ARGS; k++)
        re_jw_cstr(w, re_cc_arg_reg_name(st.cc, st.arg_regs[k]));
    re_jw_arr_end(w);
    if (st.uses_frame_ptr)
        re_jw_kbool(w, "frame_ptr", true);
    if (st.tail_call)
        re_jw_kbool(w, "tail_call", true);
    if (f->name.n)
        re_jw_kstr(w, "name", f->name);
    // The library a signature named, when one did. A name on its own says what the
    // function is called; the module says which evidence produced that name.
    if (f->module.n)
        re_jw_kstr(w, "module", f->module);
    if (xs) {
        re_vec_t strs;
        re_vec_init(&strs, sizeof(uint32_t));
        re_jw_ku64(w, "strings", re_xref_func_strings(xs, f, ctx->arena, &strs));
        re_vec_truncate(&strs, 0);
    }
    emit_flags(w, f->flags);
    re_jw_obj_end(w);
}

int re_cmd_funcs(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    if (re_report_wanted(ctx))
        return re_render_funcs(ctx, path);
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_xref_build(&code, &scan, &pe, ctx->arena, &xs);
    const char *sigfile = re_cmd_positional(argc, argv, 1);
    re_flirt_load_stat_t stat;
    size_t named = re_prep_names(ctx, sigfile, &code, &scan, &stat);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "funcs", f.whole, &pe);
    re_jw_ku64(&w, "named", named);
    re_jw_ku64(&w, "signatures", stat.before + stat.loaded);
    if (sigfile) {
        re_jw_kstr(&w, "signature_file", re_str(sigfile));
        re_jw_ku64(&w, "signatures_loaded", stat.loaded);
        if (stat.rejected)
            re_jw_ku64(&w, "signatures_rejected", stat.rejected);
    }
    re_jw_key(&w, "functions");
    re_jw_arr(&w);
    size_t shown = 0;
    size_t total = RE_VEC_LEN(&scan.funcs);
    for (size_t i = ctx->offset; i < total && shown < ctx->limit; i++, shown++) {
        const re_func_t *fn = re_func_at(&scan, i);
        emit_func(ctx, &code, &w, fn, re_func_edge_count(&scan, fn), &xs, &pe);
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "total", total);
    re_jw_kbool(&w, "truncated", shown < total);
    re_jw_ku64(&w, "edges", RE_VEC_LEN(&scan.edges));
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

// The flags a reference carries, as names. Same reasoning as the function flags:
// a reader should not have to know which bit means import.
static void emit_ref_flags(re_jw_t *w, uint8_t flags) {
    static const struct {
        uint8_t bit;
        const char *name;
    } kNames[] = {
        {RE_XRF_CODE, "code"},     {RE_XRF_IMPORT, "import"}, {RE_XRF_EXPORT, "export"},
        {RE_XRF_STRING, "string"}, {RE_XRF_DATA, "data"},     {RE_XRF_OUTSIDE, "outside"},
        {RE_XRF_JTABLE, "jtable"},
    };
    re_jw_key(w, "flags");
    re_jw_arr(w);
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        if (flags & kNames[i].bit)
            re_jw_str(w, re_str(kNames[i].name));
    }
    re_jw_arr_end(w);
}

static const char *kind_name(uint8_t k) {
    switch (k) {
        case RE_XR_CALL:
            return "call";
        case RE_XR_JUMP:
            return "jump";
        case RE_XR_COND:
            return "cond";
        default:
            return "data";
    }
}

static void emit_ref(re_jw_t *w, const re_xref_t *r, long func_index) {
    re_jw_obj(w);
    re_jw_khex(w, "from", r->from, 16);
    re_jw_khex(w, "to", r->to, 16);
    re_jw_ku64(w, "rva", r->rva);
    re_jw_kcstr(w, "kind", kind_name(r->kind));
    if (r->name.n)
        re_jw_kstr(w, "name", r->name);
    if (func_index >= 0)
        re_jw_ku64(w, "func", (uint64_t)func_index);
    emit_ref_flags(w, r->flags);
    re_jw_obj_end(w);
}

// Emit one direction of the answer. A function is queried by its body, because
// the instructions that make the references are spread through it; anything else
// is an exact address. indices holds the fwd indices when the subject is a
// function and is ignored otherwise.
static void emit_side(re_jw_t *w, const re_xrefset_t *xs, const re_fscan_t *scan, const char *key,
                      bool from_side, uint64_t subject, uint64_t span, const re_vec_t *indices) {
    // The count comes from the range query when there is a range, and from the
    // exact lookup otherwise, so a non function subject still reports its own
    // references rather than silently reporting none.
    size_t n = span ? RE_VEC_LEN(indices)
                    : (from_side ? re_xref_from_count(xs, subject) : re_xref_to_count(xs, subject));
    re_jw_key(w, key);
    re_jw_arr(w);
    for (size_t i = 0; i < n; i++) {
        const re_xref_t *r = NULL;
        if (span)
            r = RE_VEC_PTR(&xs->fwd, re_xref_t, RE_VEC_AT(indices, uint32_t, i));
        else
            r = from_side ? re_xref_from_at(xs, subject, i) : re_xref_to_at(xs, subject, i);
        if (r)
            emit_ref(w, r, re_func_index_of(scan, from_side ? r->to : r->from));
    }
    re_jw_arr_end(w);
}

// The subject is one address, given as an RVA or a virtual address. xrefs to it
// are the question worth asking, and the callers are the useful part of the
// answer, so both directions come back.
// The window a subject's references are searched over, and the fields describing it.
// A subject inside a function is searched over that whole function, which is what a
// reader asking about a function means. A subject outside every function - a string, a
// constant, a vtable slot, which is the normal case for the things people actually
// want xrefs for - is searched at its own address. It used to be searched at a window
// of zero, which skipped the query and reported no references at all, so every string
// in every binary looked like nothing pointed at it.
static uint64_t subject_span(const re_fscan_t *scan, uint64_t subject, bool *is_func) {
    long fi = re_func_index_of(scan, subject);
    *is_func = fi >= 0;
    if (fi < 0)
        return 1;
    return re_func_at(scan, (size_t)fi)->size;
}

int re_cmd_xrefs(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_vec_t into;
    re_vec_t outof;
    uint64_t subject = 0;
    uint64_t span = 0;
    // argv[0] is the file, which main already passed as path, so an address is
    // the second argument. With only the file there is nothing to look up.
    const char *pos = re_cmd_positional(argc, argv, 1);
    bool have = pos != NULL;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_xref_build(&code, &scan, &pe, ctx->arena, &xs);
    if (have && !re_parse_addr(ctx, re_str(pos), &pe, &subject)) {
        re_file_close(&f);
        return re_err_exit_code(RE_E_USAGE);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "xrefs", f.whole, &pe);
    re_jw_ku64(&w, "refs", RE_VEC_LEN(&xs.fwd));
    re_jw_ku64(&w, "indirect", xs.n_indirect);
    if (!have) {
        re_jw_ku64(&w, "total", RE_VEC_LEN(&xs.fwd));
        re_jw_kbool(&w, "truncated", false);
        re_jw_obj_end(&w);
        re_jw_flush(&w, re_ctx_out(ctx));
        re_file_close(&f);
        return 0;
    }
    long fi = re_func_index_of(&scan, subject);
    re_jw_khex(&w, "subject", subject, 16);
    re_jw_ku64(&w, "subject_rva", subject - code.base);
    {
        bool in_func = false;
        span = subject_span(&scan, subject, &in_func);
        if (in_func)
            re_jw_ku64(&w, "subject_func", (uint64_t)fi);
        else
            re_jw_kbool(&w, "subject_data", true);
    }
    re_jw_ku64(&w, "subject_span", span);
    re_vec_init(&into, sizeof(uint32_t));
    re_vec_init(&outof, sizeof(uint32_t));
    re_xref_into(&xs, ctx->arena, subject, span, 0, &into);
    re_xref_out_of(&xs, ctx->arena, subject, span, 0, &outof);
    emit_side(&w, &xs, &scan, "called_from", false, subject, span, &into);
    emit_side(&w, &xs, &scan, "refers_to", true, subject, span, &outof);
    re_jw_ku64(&w, "total", RE_VEC_LEN(&into) + RE_VEC_LEN(&outof));
    re_jw_kbool(&w, "truncated", false);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

// Every jump table found, with its case targets. The count is only reported when
// the run of targets ended, so this never invents a case number.
int re_cmd_jtables(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_vec_t tables;
    (void)argc;
    (void)argv;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_vec_init(&tables, sizeof(re_jtable_t));
    re_func_scan(&code, ctx->arena, &scan);
    size_t total = re_jtable_scan(&code, &scan, ctx->arena, &tables);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "jtables", f.whole, &pe);
    re_jw_key(&w, "tables");
    re_jw_arr(&w);
    size_t shown = 0;
    for (size_t i = 0; i < total && shown < ctx->limit; i++, shown++) {
        const re_jtable_t *t = RE_VEC_PTR(&tables, re_jtable_t, i);
        re_jw_obj(&w);
        re_jw_khex(&w, "table", t->table_va, 16);
        re_jw_ku64(&w, "table_rva", t->table_va - code.base);
        re_jw_khex(&w, "dispatch", t->at, 16);
        re_jw_khex(&w, "func", t->func_va, 16);
        re_jw_ku64(&w, "entries", t->count);
        re_jw_ku64(&w, "entry_width", t->width);
        re_jw_ku64(&w, "encoding", t->encoding);
        // The bounds check in front of the dispatch counts the cases the source
        // spells out, which for a two level table is more than the entries. Both
        // are reported because neither alone describes the switch.
        re_jw_ku64(&w, "case_max", t->bound);
        re_jw_key(&w, "targets");
        re_jw_arr(&w);
        for (uint32_t k = 0; k < t->count && k < 64; k++)
            re_jw_hex(&w, re_jtable_target(&code, t, k), 16);
        re_jw_arr_end(&w);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "total", total);
    re_jw_kbool(&w, "truncated", shown < total);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}
// Where to start, and how many bytes to cover. With no address the entry point is
// the subject, and a function subject is bounded by the function rather than run on
// into whatever data follows it.
static bool disasm_span(re_ctx_t *ctx, const re_pe_t *pe, const char *pos, uint64_t *at,
                        uint64_t *span) {
    if (pos) {
        if (!re_parse_addr(ctx, re_str(pos), pe, at))
            return false;
        *span = ctx->len ? ctx->len : 256;
        return true;
    }
    if (!pe->entry_rva) {
        RE_ERR_SET(ctx->err, RE_E_MALFORMED, "no entry point, pass an address");
        return false;
    }
    *at = pe->image_base + pe->entry_rva;
    *span = ctx->len ? ctx->len : 256;
    return true;
}

// One instruction, rendered and emitted. Text is the backend's job, reached
// through the vtable, so a caller never needs to know which architecture it is
// looking at.
static void emit_insn(re_ctx_t *ctx, re_code_t *code, re_strbuf_t *line, re_jw_t *w, uint64_t va,
                      const re_insn_t *in) {
    re_strbuf_clear(line);
    code->dis->render(code->dis->ctx, in, ctx->arena, line);
    re_jw_obj(w);
    re_jw_khex(w, "va", va, 16);
    re_jw_ku64(w, "rva", va - code->base);
    re_jw_ku64(w, "len", in->size);
    re_jw_kstr(w, "text", re_str(line->p ? line->p : ""));
    re_jw_kcstr(w, "kind",
                in->is_return   ? "ret"
                : in->is_call   ? "call"
                : in->is_branch ? "branch"
                                : "other");
    if (in->has_target)
        re_jw_khex(w, "target", in->target, 16);
    if (in->imm)
        re_jw_khex(w, "imm", (uint64_t)in->imm, 16);
    if (in->has_mem)
        re_jw_khex(w, "mem", in->mem, 16);
    re_jw_obj_end(w);
}

// Disassemble from an address, or the entry point when none is given. The listing
// covers one function so a stray data byte cannot masquerade as an instruction.
int re_cmd_disasm(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_strbuf_t line;
    uint64_t at = 0;
    uint64_t span = 256;
    size_t shown = 0;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    if (!disasm_span(ctx, &pe, re_cmd_positional(argc, argv, 1), &at, &span)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    long fi = re_func_index_of(&scan, at);
    if (fi >= 0 && !ctx->len) {
        span = re_func_at(&scan, (size_t)fi)->size;
        if (span > 512)
            span = 512;
    }
    re_strbuf_init(&line, ctx->arena);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "disasm", f.whole, &pe);
    re_jw_khex(&w, "start", at, 16);
    if (fi >= 0)
        re_jw_ku64(&w, "func", (uint64_t)fi);
    re_jw_key(&w, "insns");
    re_jw_arr(&w);
    for (uint64_t va = at; va < at + span && shown < ctx->limit;) {
        re_insn_t in;
        if (!re_code_insn(&code, va, &in))
            break;
        emit_insn(ctx, &code, &line, &w, va, &in);
        va += in.size;
        shown++;
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "total", shown);
    re_jw_kbool(&w, "truncated", shown >= ctx->limit);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}
