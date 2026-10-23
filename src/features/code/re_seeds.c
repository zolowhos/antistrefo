// re_seeds.c - the starts a walk from the entry point never reaches.
// Module: feature (C11).
// Owns: the import thunk scan, the TLS callback list, driver naming, data pointers.
// Depends: re_seeds.h. Every seed is bytes or a table the image states, so a seed
// that turns out not to be a function is discarded by the walk rather than reported.
#include "features/code/re_seeds.h"

#include "utils/text/re_strbuf.h"

// The IRP major function offsets in a DRIVER_OBJECT, in order. These are all the
// slots a driver can fill in before the object is handed to the kernel, and the names
// are the ones the DDK uses, so a reader comparing this report with the documentation
// sees the same words rather than a private spelling.
static const char *const kIrpNames[] = {
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
};
#define RE_IRP_SLOTS ((int64_t)(sizeof(kIrpNames) / sizeof(kIrpNames[0])))
#define RE_IRP_LAST (RE_IRP_SLOTS - 1)

#define RE_TLS_CALLBACK_MAX 64u

static void add_seed(re_arena_t *a, re_vec_t *out, uint64_t va, re_str_t name, const char *module) {
    re_seed_t s;
    if (va == 0)
        return;
    s.va = va;
    s.name = name;
    s.module = re_str(module);
    RE_VEC_PUSH(out, a, s);
}

// One 64-bit value at a file offset, or false when it lies outside the file. The
// reads here are over data sections, so they go through the file span rather than
// through the code map, which only answers for executable bytes.
static bool rd64(re_span_t img, uint64_t off, uint64_t *out) {
    const uint8_t *p;
    if (off + 8u > img.n)
        return false;
    p = (const uint8_t *)img.p + off;
    *out = (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
    return true;
}

// A name bound to an address, for the IAT. One shape serves every lookup in this
// file, so there is exactly one lookup routine.
typedef struct {
    uint64_t va;
    re_str_t name;
} slot_t;

static int cmp_slot(const void *a, const void *b, void *ctx) {
    const slot_t *x = (const slot_t *)a;
    const slot_t *y = (const slot_t *)b;
    (void)ctx;
    if (x->va < y->va)
        return -1;
    return x->va > y->va ? 1 : 0;
}

static const slot_t *find_slot(const re_vec_t *v, uint64_t va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(v);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const slot_t *e = RE_VEC_PTR(v, slot_t, mid);
        if (va < e->va)
            hi = mid;
        else if (va > e->va)
            lo = mid + 1;
        else
            return e;
    }
    return NULL;
}

// One entry per IAT slot, which is how code reaches an import: not by naming the
// symbol but by loading the slot's address. An IAT is data, so this is the one table
// in the image that says which imported function a piece of code calls.
static void build_iat(const re_pe_t *pe, re_arena_t *a, re_vec_t *out) {
    size_t step = pe->pe32plus ? 8u : 4u;
    for (size_t m = 0; m < RE_VEC_LEN(&pe->imports); m++) {
        const re_pe_imp_t *imp = RE_VEC_PTR(&pe->imports, re_pe_imp_t, m);
        if (!imp->first_thunk)
            continue;
        for (uint32_t i = 0; i < imp->n_syms; i++) {
            slot_t s;
            if (imp->first_sym + i >= RE_VEC_LEN(&pe->syms))
                break;
            s.va = pe->image_base + imp->first_thunk + i * step;
            s.name = RE_VEC_AT(&pe->syms, re_str_t, imp->first_sym + i);
            RE_VEC_PUSH(out, a, s);
        }
    }
    re_vec_sort(out, cmp_slot, NULL);
}

// j_<api>, the conventional label for a jump through an import slot, so a reader
// recognizes the thunk without looking the address up. Built through a string buffer
// because the name is two pieces and the arena owns the result.
static re_str_t thunk_name(re_arena_t *a, re_str_t sym) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, a);
    re_strbuf_puts(&sb, "j_");
    re_strbuf_put_re_str(&sb, sym);
    return re_strn(re_arena_strndup(a, sb.p, sb.len), sb.len);
}

// A thunk is a jump through an import slot: FF 25 with a RIP relative displacement,
// six bytes on x86-64. The scan is a byte pattern rather than a decode because it
// must work on bytes no walk has reached, and the slot decides whether it is a thunk
// at all: a stray FF 25 resolves to something that is not an IAT slot and is dropped.
static void seed_thunks(const re_code_t *code, re_arena_t *a, const re_vec_t *iat, re_vec_t *out) {
    uint64_t va = 0;
    uint64_t len = 0;
    for (uint16_t r = 0; re_code_range(code, r, &va, &len); r++) {
        for (uint64_t off = 0; off + 6u <= len; off++) {
            re_span_t b;
            int32_t disp;
            const slot_t *slot;
            if (!re_code_at(code, va + off, &b) || b.n < 6u)
                break;
            if (b.p[0] != 0xFF || b.p[1] != 0x25)
                continue;
            disp = (int32_t)((uint32_t)b.p[2] | ((uint32_t)b.p[3] << 8) | ((uint32_t)b.p[4] << 16) |
                             ((uint32_t)b.p[5] << 24));
            slot = find_slot(iat, va + off + 6u + (uint64_t)(int64_t)disp);
            if (!slot)
                continue;
            add_seed(a, out, va + off, thunk_name(a, slot->name), RE_SEED_MODULE_IMPORT);
            off += 5u;
        }
    }
}

// The TLS callback list. It is a table of absolute addresses terminated by zero, so
// each one is turned back into an address in this image before it is used; an entry
// that lands outside the image is dropped. A callback runs before the entry point, so
// nothing else in the report would ever mention it.
static void seed_tls(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vec_t *out) {
    uint64_t dir_off = 0;
    uint64_t at = 0;
    uint64_t field = pe->pe32plus ? 0x18u : 0x0Cu; // AddressOfCallBacks
    if (pe->n_dirs <= RE_PE_DD_TLS || pe->dd_rva[RE_PE_DD_TLS] == 0)
        return;
    if (!re_pe_rva2off(pe, pe->dd_rva[RE_PE_DD_TLS], &dir_off))
        return;
    if (!rd64(pe->img, dir_off + field, &at) || at <= pe->image_base)
        return;
    if (!re_pe_rva2off(pe, (uint32_t)(at - pe->image_base), &at))
        return;
    for (uint32_t i = 0; i < RE_TLS_CALLBACK_MAX; i++) {
        uint64_t cb = 0;
        re_strbuf_t sb;
        if (!rd64(pe->img, at + i * 8u, &cb) || cb == 0)
            break;
        if (cb < pe->image_base || cb - pe->image_base >= pe->size_of_image)
            continue;
        if (!re_code_in_code(code, cb))
            continue;
        re_strbuf_init(&sb, a);
        re_strbuf_appendf(&sb, "tls_callback_%u", (unsigned)i);
        add_seed(a, out, cb, re_strn(re_arena_strndup(a, sb.p, sb.len), sb.len),
                 RE_SEED_MODULE_TLS);
    }
}

// The entry point of a driver. A native image with no exports is a driver, and the
// kernel calls its entry with the driver object rather than any caller in the file,
// so nothing in the image points at it. The name is the one the DDK documents.
static void seed_driver(const re_pe_t *pe, re_arena_t *a, re_vec_t *out) {
    if (!pe->entry_rva || pe->subsystem != 1)
        return; // 1 is the native subsystem: no Win32, no user mode
    if (RE_VEC_LEN(&pe->exports) != 0)
        return; // an exported native image is a kernel library, not a driver
    add_seed(a, out, pe->image_base + pe->entry_rva, re_str("DriverEntry"), RE_SEED_MODULE_DRIVER);
}

// Code pointers in data. A vtable, a dispatch table and a callback list are all the
// same fact: the compiler wrote the address of a function where nothing branches to
// it. The value has to land in an executable section and has to decode to be kept,
// which is what stops the table of small integers every image has from filling the
// seed list with noise.
static void seed_pointers(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vec_t *out) {
    size_t n = 0;
    for (uint16_t i = 0; i < pe->n_sec && (uint64_t)n < code->lim.ptr_seeds; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        uint64_t end;
        uint64_t bytes = s->rsize < s->vsize ? s->rsize : s->vsize;
        if ((s->chars & (RE_SEC_EXEC | RE_SEC_CODE)) != 0)
            continue; // executable: this is code, and a walk reaches it
        end = (uint64_t)s->rptr + bytes;
        for (uint64_t off = s->rptr; off + 8u <= end; off += 8u) {
            uint64_t v = 0;
            re_insn_t in;
            if (!rd64(pe->img, off, &v))
                break;
            if (v < pe->image_base || v - pe->image_base >= pe->size_of_image)
                continue;
            if (!re_code_in_code(code, v) || re_code_hostile(code, v) ||
                !re_code_insn(code, v, &in))
                continue;
            add_seed(a, out, v, re_str(""), RE_SEED_MODULE_POINTER);
            n++;
        }
    }
}

void re_seed_collect(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vec_t *out) {
    re_vec_t iat;
    re_vec_init(&iat, sizeof(slot_t));
    build_iat(pe, a, &iat);
    seed_thunks(code, a, &iat, out);
    seed_tls(pe, code, a, out);
    seed_driver(pe, a, out);
    seed_pointers(pe, code, a, out);
    re_vec_truncate(&iat, 0);
}

// One store into a slot that could be a dispatch entry: which register held the
// object, which slot, and what was written there.
typedef struct {
    uint64_t base;
    uint64_t at; // the store instruction, so a run can be told from a coincidence
    uint64_t target;
    uint32_t slot;
} irp_ev_t;

#define RE_IRP_EV_MAX 8192u
#define RE_IRP_WINDOW 64u // events apart a run may span and still be one table
#define RE_IRP_SPAN 512u  // code bytes apart the stores may lie and still be a run
// A driver fills most of the table, so a run has to cover ten slots before it is
// taken as one. Four matched a table of function pointers in a class constructor and
// a callback list in a DLL, neither of which is a dispatch table, and a name that is
// wrong is worse than no name at all.
#define RE_IRP_MIN_SLOTS 10u

static int cmp_ev(const void *a, const void *b, void *ctx) {
    const irp_ev_t *x = (const irp_ev_t *)a;
    const irp_ev_t *y = (const irp_ev_t *)b;
    (void)ctx;
    if (x->base != y->base)
        return x->base < y->base ? -1 : 1;
    if (x->at != y->at)
        return x->at < y->at ? -1 : 1;
    if (x->slot != y->slot)
        return x->slot < y->slot ? -1 : 1;
    return x->target < y->target ? -1 : (x->target > y->target ? 1 : 0);
}

// The lea/store pairs that could be a driver filling its dispatch table. A lea of a
// code address is tracked per register, and the store that follows it into an
// eight-byte slot of the object decides whether it is one: the displacement range is
// the DRIVER_OBJECT's, which is the whole reason this can be read at all.
static void collect_irp(const re_code_t *code, re_arena_t *a, re_vec_t *ev) {
    uint64_t lea[16];
    uint64_t va = 0;
    uint64_t len = 0;
    for (size_t i = 0; i < 16; i++)
        lea[i] = 0;
    re_vec_truncate(ev, 0);
    for (uint16_t r = 0; re_code_range(code, r, &va, &len); r++) {
        for (uint64_t at = va; at < va + len;) {
            re_insn_t in;
            if (!re_code_insn(code, at, &in) || in.size == 0) {
                at++;
                continue;
            } // Only instructions the walk decoded as part of a function. A linear
            // decode of the whole image also walks through data, where the same bytes
            // decode to the same plausible pairs, and a table read out of a data
            // section would be a table that does not exist.
            if (!re_code_covered(code, at, in.size)) {
                at += in.size;
                continue;
            }
            if (in.insn_id == 0x008D && in.rip_rel && in.reg < 16 && in.has_mem)
                lea[in.reg] = in.mem; // lea reg,[rip+target]

            else if (in.insn_id == 0x0089 && in.is_mem && in.opsize == 8 && in.base < 16 &&
                     in.disp >= 0 && in.disp <= (int64_t)(RE_IRP_LAST * 8) && (in.disp % 8) == 0 &&
                     lea[in.reg] != 0 && re_code_in_code(code, lea[in.reg]) &&
                     ev->len < RE_IRP_EV_MAX) {
                irp_ev_t e;
                e.base = in.base;
                e.at = at;
                e.target = lea[in.reg];
                e.slot = (uint32_t)(in.disp / 8);
                RE_VEC_PUSH(ev, a, e);
            }
            at += in.size;
        }
    }
}

// A run of stores into the same object at four or more different slots, close together
// in the code, is a table. One store is a field of some other structure and is
// deliberately not named: the offset alone cannot tell a dispatch routine from a
// counter, and a name that is wrong is worse than no name at all. The address test is
// what makes it a run: the same register holding four different objects in four
// different functions is not a table.
static void emit_irp(re_arena_t *a, const re_vec_t *ev, re_vec_t *out) {
    size_t i = 0;
    while (i < RE_VEC_LEN(ev)) {
        uint32_t seen[RE_IRP_WINDOW];
        size_t picked = 0;
        size_t j = i;
        while (j < RE_VEC_LEN(ev) && j < i + RE_IRP_WINDOW) {
            const irp_ev_t *e = RE_VEC_PTR(ev, irp_ev_t, j);
            bool dup = false;
            if (e->base != RE_VEC_PTR(ev, irp_ev_t, i)->base)
                break;
            if (e->at - RE_VEC_PTR(ev, irp_ev_t, i)->at > (uint64_t)RE_IRP_SPAN)
                break; // far apart in the code: another site, not this table
            for (size_t k = 0; k < picked; k++)
                dup = dup || seen[k] == e->slot;
            if (!dup)
                seen[picked++] = e->slot;
            j++;
        }
        if (picked >= RE_IRP_MIN_SLOTS) {
            for (size_t k = i; k < j; k++) {
                const irp_ev_t *e = RE_VEC_PTR(ev, irp_ev_t, k);
                add_seed(a, out, e->target, re_str(kIrpNames[e->slot]), RE_SEED_MODULE_IRP);
            }
        }
        i = j;
    }
}

void re_seed_irp(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vec_t *out) {
    re_vec_t ev;
    // A driver object only exists in the native subsystem. Anywhere else a run of
    // lea and store pairs is some other kind of table, and the names below would be
    // the wrong names for it.
    if (pe->subsystem != 1)
        return;
    re_vec_init(&ev, sizeof(irp_ev_t));
    collect_irp(code, a, &ev);
    re_vec_sort(&ev, cmp_ev, NULL);
    emit_irp(a, &ev, out);
    re_vec_truncate(&ev, 0);
}

bool re_name_is_seed(re_str_t module) {
    return re_str_eq_cstr(module, RE_SEED_MODULE_DRIVER) ||
           re_str_eq_cstr(module, RE_SEED_MODULE_IRP) ||
           re_str_eq_cstr(module, RE_SEED_MODULE_IMPORT) ||
           re_str_eq_cstr(module, RE_SEED_MODULE_TLS) ||
           re_str_eq_cstr(module, RE_SEED_MODULE_POINTER);
}
