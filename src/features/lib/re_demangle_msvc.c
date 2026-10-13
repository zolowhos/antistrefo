// re_demangle_msvc.c - Microsoft decorated form, the free functions only.
// Module: feature (C11).
// Owns: the MSVC name, calling convention and type code parser.
// Depends: re_demangle.h, re_str, re_strbuf, re_vec. Refuses anything it cannot
// read rather than guessing, so an unrecognised code keeps its raw symbol.
#include "features/lib/re_demangle.h"

#include <stdbool.h>
#include <stddef.h>

#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

// The parser state. Output goes through sink so a nested type can be rendered
// into a scratch buffer and measured before it is committed to out.
typedef struct {
    const char *p;
    const char *end;
    bool ok;
    re_strbuf_t out;
    re_strbuf_t *sink;
} mv_t;

static void mv_putc(mv_t *s, char c) {
    if (!re_strbuf_putc(s->sink, c))
        s->ok = false;
}

static void mv_putn(mv_t *s, const char *p, size_t n) {
    if (!re_strbuf_append(s->sink, p, n))
        s->ok = false;
}

static void mv_puts(mv_t *s, const char *text) {
    mv_putn(s, text, re_str(text).n);
}

static bool at(mv_t *s, char c) {
    return s->p < s->end && *s->p == c;
}

// True when the input starts with code, consuming it when it matches.
static bool take(mv_t *s, const char *code) {
    size_t n = re_str(code).n;
    if ((size_t)(s->end - s->p) < n)
        return false;
    for (size_t j = 0; j < n; j++) {
        if (s->p[j] != code[j])
            return false;
    }
    s->p += n;
    return true;
}

// Calling conventions that actually appear in user code. Anything not listed
// yields nothing rather than an invented name. The longer codes are tried
// first because the one letter YA is a prefix of all of them. YAX, IA and IZ
// are deliberately absent: they are indistinguishable from YA followed by a
// void return and an empty parameter list, and guessing loses the real one.
static const struct {
    const char *code;
    const char *name;
} kCallConv[] = {
    {"YAS", "__stdcall"}, {"YAU", "__thiscall"}, {"YAQ", "__vectorcall"},
    {"YAA", "__cdecl"},   {"YA", "__cdecl"},     {"QEAA", "__cdecl"},
    {"QEBA", "__cdecl"},  {"QEAI", "__cdecl"},   {"QEAX", "__cdecl"},
};

// The primitive type encodings, which are every code that is not a class, a
// pointer or void. Kept as a table so the mapping is auditable in one place.
static const struct {
    const char *code;
    const char *name;
} kPrim[] = {{"C", "signed char"},
             {"D", "char"},
             {"E", "unsigned char"},
             {"F", "short"},
             {"G", "unsigned short"},
             {"H", "int"},
             {"I", "unsigned int"},
             {"J", "long"},
             {"K", "unsigned long"},
             {"M", "float"},
             {"N", "double"},
             {"O", "long double"},
             {"_D", "int64"},
             {"_E", "unsigned __int64"},
             {"_N", "bool"},
             {"_W", "wchar_t"},
             {NULL, NULL}};

static bool mv_primitive(mv_t *s) {
    for (size_t i = 0; kPrim[i].name; i++) {
        if (!take(s, kPrim[i].code))
            continue;
        mv_puts(s, kPrim[i].name);
        return true;
    }
    return false;
}

// V class, U struct, T union, W enum. All four are written out by name.
static bool is_user_class(char c) {
    return c == 'V' || c == 'U' || c == 'T' || c == 'W';
}

// Defined below, used above by the name parser.
static void mv_skip_backref(mv_t *s);

static const char *class_label(char kind) {
    if (kind == 'U')
        return " struct";
    if (kind == 'T')
        return " union";
    if (kind == 'W')
        return " enum";
    // A class gets no keyword. In C++ a declaration does not need one, and
    // every other tool omits it, so printing one only makes the renderings disagree.
    return "";
}

static void mv_class(mv_t *s);
static void mv_pointer(mv_t *s);

// ?AV, ?AU, ?AT and ?AW all carry the type by name. The name runs to the next
// @ and may itself be a nested chain, which is why this cannot be a table. The
// kind has already been consumed by the caller, inline or after ?A.
static void mv_user_class(mv_t *s, char kind) {
    const char *label = class_label(kind);
    (void)kind;
    while (s->ok && s->p < s->end && *s->p != '@') {
        char c = *s->p;
        if (c == '?') {
            s->p++;
            continue;
        }
        if (c == '@')
            break;
        mv_putc(s, c);
        s->p++;
    }
    while (s->ok && s->p < s->end && *s->p == '@')
        s->p++;
    mv_skip_backref(s);
    if (label[0])
        mv_puts(s, label);
}

// A backreference is digits standing for a name already used, and it is closed by
// the @ that ends the type. It has to be skipped: left in place the digits are read
// as the next type, and the rest of the symbol stops parsing.
static void mv_skip_backref(mv_t *s) {
    while (s->p < s->end && (*s->p == '?' || *s->p == '$' || (*s->p >= '0' && *s->p <= '9')))
        s->p++;
    if (s->p < s->end && *s->p == '@')
        s->p++;
}

// A reference and the const that may follow it. Only consumed when a reference
// marker is actually there: E on its own is the encoding for unsigned char, so
// treating every leading E as const would silently turn an unsigned char
// parameter into a const-qualified something else.
static void mv_cv_ref(mv_t *s, bool *is_ref, bool *is_const) {
    if (!at(s, 'A') && !at(s, 'Q') && !at(s, 'R'))
        return;
    *is_ref = true;
    s->p++;
    while (at(s, 'E') || at(s, 'B')) {
        *is_const = true;
        s->p++;
    }
}

// P introduces a pointer. The run of qualifier codes that follows carries the cv
// and alignment of the pointee; the const is kept so the declaration reads as
// "char const *" rather than "char *", and the rest are dropped because they may
// sit on the far side of the indirection.
static void mv_pointer(mv_t *s) {
    bool is_const = false;
    while (s->p < s->end) {
        char c = *s->p;
        if (c == 'E' || c == 'B') {
            is_const = true;
            s->p++;
            continue;
        }
        // C is volatile and A a further reference. D is deliberately absent: it is
        // the encoding for char, a type rather than a modifier, and skipping it ate
        // the pointee before the type parser ever saw it, which is why a symbol
        // taking a const char* was rejected outright.
        if (c == 'C' || c == 'A') {
            s->p++;
            continue;
        }
        break;
    }
    mv_class(s);
    if (is_const)
        mv_puts(s, " const");
    mv_puts(s, " *");
}

static void mv_class(mv_t *s) {
    bool is_ref = false;
    bool is_const = false;
    if (at(s, '?') || at(s, '@')) {
        if (s->p + 1 < s->end && is_user_class(s->p[1])) {
            char kind = s->p[1];
            s->p += 2;
            mv_user_class(s, kind);
            return;
        }
        s->ok = false;
        return;
    }
    mv_cv_ref(s, &is_ref, &is_const);
    // A class by name also appears with no ?A in front of it, as a return type or a
    // parameter does. Only the leading form used to be accepted, so every symbol
    // mentioning a class outside the name itself was rejected.
    if (s->p < s->end && is_user_class(*s->p)) {
        char kind = *s->p;
        s->p++;
        mv_user_class(s, kind);
    } else if (at(s, 'X')) {
        s->p++;
        mv_puts(s, "void");
    } else if (at(s, 'F')) {
        s->p++;
        if (s->p < s->end)
            s->p++;
        mv_puts(s, "void");
        if (s->p < s->end)
            s->p++;
    } else if (at(s, 'D')) {
        s->p++;
        if (s->p < s->end && *s->p == 'P') {
            s->p++;
            mv_pointer(s);
            return;
        }
        if (s->p < s->end && *s->p == 'G') {
            s->p++;
            mv_puts(s, "unsigned long long");
            return;
        }
        // The code has already been consumed, so the primitive table cannot be asked
        // for it again; char is named directly. Leaving it to the table looked up the
        // character after the D and matched whatever followed, or nothing.
        mv_puts(s, "char");
    } else if (at(s, 'P')) {
        s->p++;
        mv_pointer(s);
    } else if (!mv_primitive(s)) {
        s->ok = false;
        return;
    }
    if (is_const)
        mv_puts(s, " const");
    if (is_ref)
        mv_puts(s, " &");
}
static void mv_type(mv_t *s) {
    if (!s->ok || s->p >= s->end) {
        s->ok = false;
        return;
    }
    mv_class(s);
}

// Copy the undecorated name, which is a chain of scope segments separated by single
// @ and closed by @@. The segments are emitted outermost first and joined with ::, so
// ?generic_category@system@boost@@ is boost::system::generic_category. Only the
// innermost segment used to be read, with one @ skipped, which left the rest of the
// chain in the stream and made every symbol in a namespace fail to parse.
#define MV_MAX_SEGS 8

static void mv_name(mv_t *s) {
    const char *segs[MV_MAX_SEGS];
    size_t lens[MV_MAX_SEGS];
    size_t n = 0;
    if (s->p < s->end && *s->p == '?') {
        s->p++;
        if (s->p < s->end && *s->p == '?')
            s->p++;
    }
    while (s->p < s->end) {
        if (*s->p == '@') {
            s->p++;
            if (s->p < s->end && *s->p == '@') {
                s->p++;
                break; // @@ closes the name
            }
            continue;
        }
        const char *start = s->p;
        while (s->p < s->end && *s->p != '@') {
            if (*s->p != '?')
                s->p++;
            else
                s->p++;
        }
        if (n < MV_MAX_SEGS) {
            segs[n] = start;
            lens[n] = (size_t)(s->p - start);
            n++;
        }
    }
    for (size_t i = n; i > 0; i--) {
        if (i != n)
            mv_puts(s, "::");
        for (size_t k = 0; k < lens[i - 1]; k++) {
            if (segs[i - 1][k] == '?')
                continue; // the nested-marker prefix, not part of the name
            mv_putc(s, segs[i - 1][k]);
        }
    }
}

// Collect every encoded type into a vec. The last one is the return value.
static void mv_collect_types(mv_t *s, re_arena_t *a, re_vec_t *types) {
    re_strbuf_t scratch;
    re_strbuf_init(&scratch, a);
    while (s->ok && s->p < s->end && *s->p != 'Z' && *s->p != '@') {
        re_strbuf_clear(&scratch);
        s->sink = &scratch;
        mv_type(s);
        s->sink = &s->out;
        if (!s->ok)
            return;
        re_str_t v =
            re_strn(re_arena_strndup(a, scratch.p ? scratch.p : "", scratch.len), scratch.len);
        RE_VEC_PUSH(types, a, v);
    }
}

// Render the parameter list. The FIRST type is the return and is dropped, not the
// last: after the call convention the encoding is the return type followed by the
// parameters, so ?f@@YAXH@Z is void f(int) and the two X's in ?foo@@YAXXZ are a void
// return and a void parameter list. Treating the last type as the return made that
// one print as f(), which is a wrong answer rather than a rejected symbol, and a
// wrong answer is worse: it looks like knowledge. A lone void in the parameter
// position is the marker for an empty list.
static void mv_signature(mv_t *s, const re_vec_t *types) {
    size_t count = RE_VEC_LEN(types);
    size_t nparams = count ? count - 1u : 0u;
    if (nparams == 1) {
        const re_str_t *only = RE_VEC_PTR(types, re_str_t, 1);
        if (re_str_eq_cstr(*only, "void"))
            nparams = 0;
    }
    mv_puts(s, "(");
    for (size_t i = 1; i <= nparams; i++) {
        if (i > 1)
            mv_puts(s, ", ");
        const re_str_t *t = RE_VEC_PTR(types, re_str_t, i);
        mv_putn(s, t->p, t->n);
    }
    mv_puts(s, ")");
}

// Everything after the calling convention, and it must consume the whole rest of
// the name. A leftover is how a wrong reading of an ambiguous code announces
// itself: otherwise it stops at the first answer that looked plausible.
static bool parse_rest(re_arena_t *a, mv_t *s, const char *cc) {
    re_vec_t types;
    re_vec_init(&types, sizeof(re_str_t));
    mv_collect_types(s, a, &types);
    if (!s->ok)
        return false;
    mv_signature(s, &types);
    if (cc[0] != 0 && !re_str_eq_cstr(re_str(cc), "__cdecl")) {
        mv_puts(s, " ");
        mv_puts(s, cc);
    }
    while (s->p < s->end && (*s->p == 'Z' || *s->p == '@'))
        s->p++;
    return s->p == s->end;
}

bool re_demangle_msvc(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    mv_t s;
    s.p = sym;
    s.end = sym + n;
    s.ok = true;
    re_strbuf_init(&s.out, a);
    s.sink = &s.out;
    // A thunk stub or a vcall thunk carries a leading @?.
    if (s.p < s.end && *s.p == '@') {
        s.p += 2;
        if (s.p >= s.end)
            return false;
    }
    mv_name(&s);
    if (!s.ok || s.p >= s.end)
        return false;
    // YAA is two different things: a three letter calling convention, or the two
    // letter YA followed by A, which opens a reference to the return type. Nothing
    // in the name says which, so every candidate is tried and only one that
    // consumes the whole signature is accepted. Committing to the first match
    // produced a signature that read correctly and was wrong; committing to the
    // last produced nothing at all.
    const char *resume = s.p;
    for (size_t i = 0; i < sizeof(kCallConv) / sizeof(kCallConv[0]); i++) {
        size_t mark = s.out.len;
        if (take(&s, kCallConv[i].code) && parse_rest(a, &s, kCallConv[i].name)) {
            char *text = re_strbuf_detach(&s.out);
            if (text && re_str(text).n) {
                *out = re_str(text);
                return true;
            }
            break;
        }
        s.p = resume;
        s.out.len = mark;
        s.ok = true;
    }
    return false;
}
