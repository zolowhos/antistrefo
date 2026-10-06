// re_dc_print.c - turning varnodes and ops into text.
// Module: feature (C11).
// Owns: the name tables, the value renderer, and the one statement writer.
// Depends: re_dc_print.h, re_disasm. A register is named through the vtable, so no
//           x86 detail appears here and a new arch needs no change to this file.
#include "features/dec/re_dc_print.h"

#include "features/meta/re_disasm.h"

#include <stdio.h>
#include <string.h>

// One stack displacement's entry, found or taken in address order so the
// declarations print sorted without a second pass. The widest width wins,
// because a byte write into a slot a qword also touches is the qword local
// with a subfield written, which is how a C programmer reads it too.
static int sw_find(const re_dc_emit_t *e, int16_t disp) {
    for (uint32_t i = 0; i < e->n_sw; i++)
        if (e->sw_disp[i] == disp)
            return (int)i;
    return -1;
}

static void sw_learn(re_dc_emit_t *e, int16_t disp, uint16_t w) {
    uint32_t i;
    int at = sw_find(e, disp);
    if (at >= 0) {
        if ((uint16_t)e->sw_w[at] < w)
            e->sw_w[at] = (uint8_t)w;
        return;
    }
    if (e->n_sw >= RE_SLOT_MAX)
        return;
    // Insert in order, so the table is sorted for the declarations.
    for (i = e->n_sw; i > 0 && e->sw_disp[i - 1] > disp; i--) {
        e->sw_disp[i] = e->sw_disp[i - 1];
        e->sw_w[i] = e->sw_w[i - 1];
    }
    e->sw_disp[i] = disp;
    e->sw_w[i] = (uint8_t)w;
    e->n_sw++;
}

// The widths a body actually used, learned before anything is printed. Every
// load and store is asked for its access width and its address, and a stack
// varnode used directly as an address counts at its own width too.
void re_dc_learn_widths(re_dc_emit_t *e, const re_ir_func_t *ir) {
    for (size_t bi = 0; bi < ir->n_blocks; bi++) {
        const re_ir_block_t *blk = &ir->blocks[bi];
        for (size_t k = 0; k < blk->n_ops; k++) {
            const re_ir_op_t *op = &blk->ops[k];
            unsigned a;
            if (op->op == RE_OP_LOAD) {
                if (op->in[0].space == RE_SPACE_STACK)
                    sw_learn(e, (int16_t)op->in[0].offset, op->out.size);
            } else if (op->op == RE_OP_STORE) {
                if (op->in[2].space == RE_SPACE_STACK)
                    sw_learn(e, (int16_t)op->in[2].offset, op->in[0].size);
            }
            for (a = 0; a < 4; a++)
                if (op->in[a].space == RE_SPACE_STACK)
                    sw_learn(e, (int16_t)op->in[a].offset, op->in[a].size ? op->in[a].size : 8);
        }
    }
}

uint8_t re_dc_slot_width(const re_dc_emit_t *e, int16_t disp) {
    int at = sw_find(e, disp);
    return at >= 0 ? e->sw_w[at] : 0;
}

const char *re_dc_local(re_dc_emit_t *e, int16_t disp) {
    unsigned m = disp < 0 ? (unsigned)(-(int)disp) : (unsigned)disp;
    snprintf(e->lname, (size_t)RE_DC_TEXT, "%s%u", disp < 0 ? "local_m" : "local_p", m);
    return e->lname;
}

// A value the emitter can print: a name we minted, a register that was read before
// it was written, or a literal. Keeping it as text is what lets the same code path
// print an operand, a right hand side and a comparison operand without caring which
// of the three it is.
const char *re_dc_val(re_dc_emit_t *e, re_varnode_t vn, char *scratch) {
    if (vn.space == RE_SPACE_CONST) {
        // A constant's value lives in the op that defined it, keyed by this id, so a
        // 64 bit value survives a 16 bit offset field and two constants never mix. An
        // address is printed in hex, because that is how every other part of the tool
        // prints one and how a reader will compare it against a disassembly.
        if (vn.offset < RE_DC_VARS) {
            if (e->caddr[vn.offset])
                snprintf(scratch, RE_DC_TEXT, "0x%llx", (unsigned long long)e->cval[vn.offset]);
            else
                snprintf(scratch, RE_DC_TEXT, "%lld", (long long)e->cval[vn.offset]);
            return scratch;
        }
        snprintf(scratch, RE_DC_TEXT, "?");
        return scratch;
    }
    if (vn.space == RE_SPACE_UNIQUE)
        return (vn.offset < RE_DC_VARS && e->uniq[vn.offset].p) ? (const char *)e->uniq[vn.offset].p
                                                                : "cond";
    if (vn.space == RE_SPACE_STACK) {
        snprintf(scratch, RE_DC_TEXT, "&%s", re_dc_local(e, (int16_t)vn.offset));
        return scratch;
    }
    if (vn.space == RE_SPACE_FLAG) {
        static const char *const kFlags[6] = {"cf", "zf", "sf", "of", "pf", "af"};
        snprintf(scratch, RE_DC_TEXT, "%s", vn.offset < 6 ? kFlags[vn.offset] : "flag");
        return scratch;
    }
    if (vn.space == RE_SPACE_IOP) {
        // A thread environment block access on Windows: the segment relative
        // offset is the identity of the location, so the offset is the name.
        snprintf(scratch, RE_DC_TEXT, "teb_%#x", (unsigned)vn.offset);
        return scratch;
    }
    if (vn.space == RE_SPACE_REG && vn.offset < RE_DC_REGS && e->reg[vn.offset].p)
        return (const char *)e->reg[vn.offset].p;
    // A register read before it was written, or one the emitter never bound. The
    // backend names it, so the output still says rax rather than r0.
    if (e->dis && e->dis->reg_name) {
        const char *n = e->dis->reg_name(e->dis->ctx, vn.offset);
        if (n)
            return n;
    }
    snprintf(scratch, RE_DC_TEXT, "r%u", vn.offset);
    return scratch;
}

re_str_t re_dc_mint(re_dc_emit_t *e, const char *prefix, uint32_t n) {
    char buf[24];
    int k = snprintf(buf, sizeof(buf), "%s%u", prefix, n);
    re_str_t s;
    s.p = (const char *)re_arena_memdup(e->a, buf, (size_t)k);
    s.n = (uint32_t)k;
    return s;
}

void re_dc_bind(re_dc_emit_t *e, re_varnode_t vn, re_str_t name) {
    if (vn.space == RE_SPACE_REG && vn.offset < RE_DC_REGS) {
        e->reg[vn.offset] = name;
        e->touched[vn.offset] = true;
    }
    // A temporary is named once, where it is defined, and every later reference to
    // it prints that same name. Without this the backend's load, operate, store for
    // a memory destination would print three unrelated names.
    if (vn.space == RE_SPACE_UNIQUE && vn.offset < RE_DC_VARS)
        e->uniq[vn.offset] = name;
}

void re_dc_fmt(char *dst, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
}

// The stack strings the deobfuscation pass decoded, printed as comments before
// the body. They name a literal the machine builds one store at a time, which
// is exactly the fact a reader cannot see in the statements that follow.
void re_dc_stackstrs(re_dc_emit_t *e, const re_flow_stat_t *fl) {
    for (size_t i = 0; i < RE_VEC_LEN(&fl->strs); i++) {
        const re_flow_str_t *s = RE_VEC_PTR(&fl->strs, re_flow_str_t, i);
        re_strbuf_puts(e->o, "    // stack string at ");
        re_strbuf_put_hex64(e->o, s->at, 16);
        re_strbuf_puts(e->o, ": \"");
        re_strbuf_puts(e->o, s->text);
        re_strbuf_puts(e->o, "\"\n");
        e->n_stmts++;
    }
}

// One unlowered instruction: a comment carrying its address and text, never
// dropped. Silence would read as "nothing happens here", which is how a
// reader is misled about a function.
void re_dc_unlowered(re_dc_emit_t *e, const re_insn_t *in) {
    re_strbuf_t txt;
    re_strbuf_init(&txt, e->a);
    e->dis->render(e->dis->ctx, in, e->a, &txt);
    re_strbuf_puts(e->o, "    // ");
    re_strbuf_put_hex64(e->o, in->addr, 16);
    re_strbuf_putc(e->o, ' ');
    re_strbuf_puts(e->o, txt.p ? txt.p : "?");
    re_strbuf_puts(e->o, "\n");
    e->n_unknown++;
    e->n_stmts++;
}

// The indentation a line of a structured body sits at: one step of four spaces per
// open brace. The flat printer leaves indent at zero, so its output is unchanged.
static void put_indent(re_dc_emit_t *e) {
    for (uint32_t i = 0; i < e->indent; i++)
        re_strbuf_puts(e->o, "    ");
}

static void note_site(re_dc_emit_t *e) {
    re_dc_site_t s;
    if (!e->sites || !e->map_va)
        return;
    s.line = (uint32_t)(e->n_stmts + 1);
    s.va = e->map_va;
    RE_VEC_PUSH(e->sites, e->a, s);
}

void re_dc_stmt(re_dc_emit_t *e, const char *fmt, ...) {
    va_list ap;
    if (e->n_stmts && e->n_stmts % 6 == 0)
        re_strbuf_puts(e->o, "\n");
    put_indent(e);
    va_start(ap, fmt);
    {
        char buf[160];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        re_strbuf_puts(e->o, buf);
    }
    va_end(ap);
    if (e->map_va)
        re_strbuf_puts(e->o, " /* @");
    if (e->map_va)
        re_strbuf_put_hex64(e->o, e->map_va, 16);
    if (e->map_va)
        re_strbuf_puts(e->o, " */");
    note_site(e);
    re_strbuf_puts(e->o, ";\n");
    e->n_stmts++;
}

void re_dc_line(re_dc_emit_t *e, const char *fmt, ...) {
    va_list ap;
    put_indent(e);
    va_start(ap, fmt);
    {
        char buf[160];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        re_strbuf_puts(e->o, buf);
    }
    va_end(ap);
    note_site(e);
    re_strbuf_puts(e->o, "\n");
    e->n_stmts++;
}

// The C spelling of a binary arithmetic op, or NULL when the op has no C form here
// and must be printed some other way. Grouped so the table and the emitter agree.
const char *re_dc_binop(re_op_kind_t k) {
    switch (k) {
        case RE_OP_INTADD:
            return "+";
        case RE_OP_INTSUB:
            return "-";
        case RE_OP_INTMUL:
            return "*";
        case RE_OP_INTDIV:
            return "/";
        case RE_OP_INTMOD:
            return "%";
        case RE_OP_INTAND:
            return "&";
        case RE_OP_INTOR:
            return "|";
        case RE_OP_INTXOR:
            return "^";
        case RE_OP_INTSHL:
            return "<<";
        case RE_OP_INTSHR:
            return ">>";
        case RE_OP_INTUDIV:
            return "/";
        case RE_OP_INTUMOD:
            return "%";
        case RE_OP_FADD:
            return "+";
        case RE_OP_FSUB:
            return "-";
        case RE_OP_FMUL:
            return "*";
        case RE_OP_FDIV:
            return "/";
        default:
            return NULL;
    }
}

// The ops without a C operator become calls to named helpers, which is honest:
// the reader sees an operation the source language has no symbol for, spelled
// the way the architecture manual spells it.
const char *re_dc_fnop(re_op_kind_t k) {
    switch (k) {
        case RE_OP_ROL:
            return "rotl";
        case RE_OP_ROR:
            return "rotr";
        case RE_OP_UMULH:
            return "umulh";
        case RE_OP_IMULH:
            return "imulh";
        case RE_OP_POPCNT:
            return "popcnt";
        case RE_OP_LZCNT:
            return "lzcnt";
        case RE_OP_TZCNT:
            return "tzcnt";
        case RE_OP_BSWAP:
            return "bswap";
        case RE_OP_BITNOT:
            return "bitnot";
        case RE_OP_MEMCPY:
            return "memcpy";
        case RE_OP_MEMSET:
            return "memset";
        default:
            return NULL;
    }
}

// The float type a cast or a declaration prints, by width.
const char *re_dc_ftype(uint16_t size) {
    return size == 8 ? "double" : "float";
}

// The name of a condition the emitter could not resolve to an expression: the
// x86 condition itself, so the reader knows exactly which flag bits mattered.
const char *re_dc_ccname(unsigned cc) {
    static const char *const k[16] = {"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                                      "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
    return cc < 16 ? k[cc] : "cc";
}

const char *re_dc_ccop(unsigned cc) {
    switch (cc) {
        case RE_CC_OP_EQ:
            return "==";
        case RE_CC_OP_NE:
            return "!=";
        case RE_CC_OP_SLT:
            return "<";
        case RE_CC_OP_SLE:
            return "<=";
        case RE_CC_OP_ULT:
            return "<";
        case RE_CC_OP_ULE:
            return "<=";
        case RE_CC_OP_SGT:
            return ">";
        case RE_CC_OP_SGE:
            return ">=";
        case RE_CC_OP_UGT:
            return ">";
        default:
            return ">=";
    }
}

// The size a load or store touches, printed so the reader can see how wide an access
// it is. A dereference without a width is a bug in the reader's code, not ours.
const char *re_dc_type(uint16_t size) {
    switch (size) {
        case 1:
            return "uint8_t";
        case 2:
            return "uint16_t";
        case 4:
            return "uint32_t";
        default:
            return "uint64_t";
    }
}

// The printed condition for a branch whose four bit condition is cc, read against
// the flag writer the lowering recorded. A real comparison decides the full
// condition set; a test decides zero and sign of its bitwise and; every result
// writing form decides zero and sign of the result it printed. Anything else is
// not derivable, and the caller prints an honest flag name instead of a plausible
// comparison that would be a wrong answer.
bool re_dc_flag_expr(const re_dc_emit_t *e, unsigned cc, char *out, size_t cap) {
    const char *l = e->cmp_l;
    const char *r = e->cmp_r;
    switch (e->flag_writer) {
        case RE_SETF_CMP:
            if (cc == RE_CC_JE)
                return re_dc_fmt(out, cap, "%s == %s", l, r), true;
            if (cc == RE_CC_JNE)
                return re_dc_fmt(out, cap, "%s != %s", l, r), true;
            if (cc == RE_CC_JB || cc == RE_CC_JBE || cc == RE_CC_JA || cc == RE_CC_JAE)
                return re_dc_fmt(out, cap, "%s %s %s", l,
                                 cc == RE_CC_JB    ? "<"
                                 : cc == RE_CC_JBE ? "<="
                                 : cc == RE_CC_JA  ? ">"
                                                   : ">=",
                                 r),
                       true;
            if (cc == RE_CC_JL || cc == RE_CC_JLE || cc == RE_CC_JG || cc == RE_CC_JGE)
                return re_dc_fmt(out, cap, "(int64_t)%s %s (int64_t)%s", l,
                                 cc == RE_CC_JL    ? "<"
                                 : cc == RE_CC_JLE ? "<="
                                 : cc == RE_CC_JG  ? ">"
                                                   : ">=",
                                 r),
                       true;
            return false;
        case RE_SETF_TEST:
            if (cc == RE_CC_JE)
                return re_dc_fmt(out, cap, "(%s & %s) == 0", l, r), true;
            if (cc == RE_CC_JNE)
                return re_dc_fmt(out, cap, "(%s & %s) != 0", l, r), true;
            if (cc == RE_CC_JS)
                return re_dc_fmt(out, cap, "(int64_t)(%s & %s) < 0", l, r), true;
            if (cc == RE_CC_JNS)
                return re_dc_fmt(out, cap, "(int64_t)(%s & %s) >= 0", l, r), true;
            return false;
        default:
            if (cc == RE_CC_JE)
                return re_dc_fmt(out, cap, "%s == 0", l), true;
            if (cc == RE_CC_JNE)
                return re_dc_fmt(out, cap, "%s != 0", l), true;
            if (cc == RE_CC_JS)
                return re_dc_fmt(out, cap, "(int64_t)%s < 0", l), true;
            if (cc == RE_CC_JNS)
                return re_dc_fmt(out, cap, "(int64_t)%s >= 0", l), true;
            return false;
    }
}
