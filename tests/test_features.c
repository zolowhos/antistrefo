// test_features.c - checks the step two features: search, demangling, time, entropy.
// Module: test (C11).
// Owns: correctness checks for re_search, re_demangle, re_time and re_entropy.
// Depends: re_core and re_utils. Prints to stdout, which is fine for a test binary.
#include "features/data/re_search.h"
#include "features/data/re_strings.h"
#include "features/lib/re_demangle.h"
#include "features/lib/re_demangle_rtti.h"
#include "utils/sys/re_entropy.h"
#include "utils/sys/re_time.h"
#include "utils/text/re_util.h"
#include "re_test.h"

#include <stdio.h>
#include <string.h>

static void test_time(void) {
    char buf[24];
    re_time_iso(0, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "1970-01-01T00:00:00Z") == 0);
    // 1262079379 is 14607 days after the epoch, which is three days short of
    // 2010, so this lands in 2009. Getting this right is why the check exists.
    re_time_iso(1262079379, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "2009-12-29T09:36:19Z") == 0);
    re_time_iso(1, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "1970-01-01T00:00:01Z") == 0);
    re_time_iso(1583020800, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "2020-03-01T00:00:00Z") == 0);
    re_time_iso(1767225600, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "2026-01-01T00:00:00Z") == 0);
    // A timestamp before the epoch, which pre 1970 builds produce.
    re_time_iso(-86400, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "1969-12-31T00:00:00Z") == 0);
    RE_CHECK_EQ_U(re_time_year(1262079379), 2009);
    RE_CHECK_EQ_U(re_time_year(0), 1970);
    RE_CHECK_EQ_U(re_time_age_years(0, 1262079379), 39);
    RE_CHECK_EQ_U(re_time_year(1767225600), 2026);
}

typedef struct {
    re_span_t img;
    size_t pattern;
    size_t needle;
    size_t wide;
    size_t imm;
    size_t main;
} hay_t;

static hay_t make_hay(uint8_t *buf) {
    static const uint8_t pat4[4] = {0xde, 0xad, 0xbe, 0xef};
    static const uint8_t needle[6] = {'N', 'E', 'E', 'D', 'L', 'E'};
    size_t n = 0;
    hay_t h;
    memcpy(buf + n, "AAAA", 4);
    n += 4;
    memcpy(buf + n, pat4, 4);
    h.pattern = n;
    n += 4;
    memcpy(buf + n, "domain", 6);
    n += 6;
    buf[n++] = ' ';
    memcpy(buf + n, "main", 4);
    h.main = n;
    n += 4;
    buf[n++] = ' ';
    memcpy(buf + n, needle, 6);
    h.needle = n;
    n += 6;
    memcpy(buf + n, needle, 6);
    h.wide = n;
    for (size_t i = 0; i < 6; i++) {
        buf[n] = needle[i];
        buf[n + 1] = 0;
        n += 2;
    }
    buf[n++] = 0xad;
    buf[n++] = 0x00;
    h.imm = n - 2;
    memcpy(buf + n, "ZZZZ", 4);
    n += 4;
    h.img = re_span(buf, n);
    return h;
}

// A wildcard byte matches anything, and a non matching literal is a miss. Bad
// and ambiguous patterns are refused rather than guessed at.
static void test_search_patterns(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    uint8_t *by = NULL;
    uint8_t *mk = NULL;
    size_t pn = 0;
    RE_CHECK(re_search_parse_pattern(a, "deadbe??", &by, &mk, &pn, NULL));
    RE_CHECK_EQ_U(pn, 4);
    RE_CHECK_EQ_U(mk[0], 0xFF);
    RE_CHECK_EQ_U(mk[3], 0);
    re_search_init(&s);
    re_search_bytes(h->img, by, mk, pn, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    RE_CHECK(re_search_parse_pattern(a, "deadbe00", &by, &mk, &pn, NULL));
    re_search_init(&s);
    re_search_bytes(h->img, by, mk, pn, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 0);
    RE_CHECK(!re_search_parse_pattern(a, "deaz", &by, &mk, &pn, NULL));
    RE_CHECK(!re_search_parse_pattern(a, "d", &by, &mk, &pn, NULL));
    RE_CHECK(!re_search_parse_pattern(a, "dead?ebe?", &by, &mk, &pn, NULL));
    RE_CHECK(re_search_parse_pattern(a, "deadbeef", &by, &mk, &pn, NULL));
    re_search_init(&s);
    re_search_bytes(h->img, by, mk, pn, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->pattern);
}

// Both endiannesses, so 0x00AD matches ad 00 and also 00 ad where the high byte
// of the preceding wide character happens to be zero.
static void test_search_immediate(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_immediate(h->img, 0xDEADBEEFu, 4, true, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->pattern);
    re_search_init(&s);
    re_search_immediate(h->img, 0x00ADu, 2, true, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    RE_CHECK_FITS(s.hits, 2);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->imm);
    if (RE_VEC_LEN(&s.hits) > 1)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 1).off, h->imm - 1);
}

// A hit list must name each offset once. The wide scan used to rebuild a run
// once per character, so one match was reported several times over.
static void check_offsets_distinct(const re_search_t *s) {
    for (size_t i = 0; i < RE_VEC_LEN(&s->hits); i++) {
        for (size_t j = i + 1; j < RE_VEC_LEN(&s->hits); j++) {
            if (RE_VEC_AT(&s->hits, re_search_hit_t, i).off ==
                RE_VEC_AT(&s->hits, re_search_hit_t, j).off)
                RE_CHECK(0 && "duplicate hit offset");
        }
    }
}

static void test_search_text(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_text(h->img, re_str("NEEDLE"), false, false, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    check_offsets_distinct(&s);
    re_search_init(&s);
    re_search_text(h->img, re_str("needle"), false, true, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    RE_CHECK_FITS(s.hits, 2);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->needle);
    if (RE_VEC_LEN(&s.hits) > 1)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 1).off, h->wide);
    re_search_init(&s);
    re_search_text(h->img, re_str("NEE.LE"), true, false, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    check_offsets_distinct(&s);
    re_search_init(&s);
    re_search_text(h->img, re_str("E"), false, false, false, 0, 0, a, &s);
    check_offsets_distinct(&s);
    RE_CHECK_EQ_U(RE_VEC_LEN(&s.hits), s.total);
}

static void test_search_signature(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_signature(h->img, re_str("main"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    RE_CHECK_FITS(s.hits, 1);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->main);
    re_search_init(&s);
    re_search_signature(h->img, re_str("doma"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 0);
}

static void test_search_limit(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_text(h->img, re_str("NEEDLE"), false, false, false, 0, 1, a, &s);
    RE_CHECK_EQ_U(RE_VEC_LEN(&s.hits), 1);
    RE_CHECK_EQ_U(s.total, 1);
    RE_CHECK(s.more);
    // The same search uncapped reports both copies and does not claim otherwise.
    re_search_init(&s);
    re_search_text(h->img, re_str("NEEDLE"), false, false, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(RE_VEC_LEN(&s.hits), 2);
    RE_CHECK_EQ_U(s.total, 2);
    RE_CHECK(!s.more);
    // The whole word matcher must not report a prefix of a longer word.
    re_search_init(&s);
    re_search_signature(h->img, re_str("main"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    re_search_init(&s);
    re_search_signature(h->img, re_str("mai"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 0);
}

static void test_search(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    uint8_t buf[256];
    hay_t h = make_hay(buf);
    test_search_patterns(&a, &h);
    test_search_immediate(&a, &h);
    test_search_text(&a, &h);
    test_search_signature(&a, &h);
    test_search_limit(&a, &h);
    re_arena_free(&a);
}

static void test_demangle_msvc(void);
static void test_demangle_rust(void);
static void test_demangle_rust_tuple(void);

static void test_demangle(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_str_t out;
    // Lengths come from strlen. Hand counting a mangled symbol is how you end
    // up debugging a truncated string that was never truncated.
#define DEMANGLE(sym) re_demangle_itanium(&a, (sym), strlen(sym), &out)
    RE_CHECK_EQ_U(re_mangle_kind("main", 4), RE_MANGLE_UNKNOWN);
    RE_CHECK_EQ_U(re_mangle_kind("_ZN3foo3barEv", 13), RE_MANGLE_ITANIUM);
    RE_CHECK_EQ_U(re_mangle_kind("?func@@YAXXZ", 12), RE_MANGLE_MSVC);
    RE_CHECK_EQ_U(re_mangle_kind("main", 4), RE_MANGLE_UNKNOWN);
    RE_CHECK_EQ_U(re_mangle_kind("_ZN3foo3barEv", 13), RE_MANGLE_ITANIUM);
    RE_CHECK_EQ_U(re_mangle_kind("?func@@YAXXZ", 12), RE_MANGLE_MSVC);
    RE_CHECK(DEMANGLE("_ZN3foo3barEv"));
    RE_CHECK(strcmp(out.p, "foo::bar()") == 0);
    // The same symbol again in the same process. imports and exports demangle
    // many symbols per run, so a parser that carried state between calls only
    // showed up on the second one, which is what this pins down.
    RE_CHECK(DEMANGLE("_ZN3foo3barEv"));
    RE_CHECK(strcmp(out.p, "foo::bar()") == 0);
    RE_CHECK(DEMANGLE("_ZN3foo3barEvi"));
    RE_CHECK(strcmp(out.p, "foo::bar(int)") == 0);
    RE_CHECK(DEMANGLE("_ZN5Outer5Inner3fooEv"));
    RE_CHECK(strcmp(out.p, "Outer::Inner::foo()") == 0);
    // A symbol that carries no parameter list: a data symbol, and the shape every Rust
    // legacy function has, whose last component is its disambiguating hash. This was
    // refused because the parser required a byte after the name, so the nested shape
    // that appears most often in the wild could not be demangled at all. The hash is
    // kept rather than removed: two instantiations of one template differ only there,
    // and dropping it would make them read as the same function.
    RE_CHECK(DEMANGLE("_ZN3foo3barE"));
    RE_CHECK(strcmp(out.p, "foo::bar") == 0);
    RE_CHECK(DEMANGLE("_ZN4core3fmt9Formatter9write_fmt17h6f7c8d9e0a1b2c3dE"));
    RE_CHECK(strcmp(out.p, "core::fmt::Formatter::write_fmt::h6f7c8d9e0a1b2c3d") == 0);
    RE_CHECK(DEMANGLE("_ZN3std2io5stdio6_print17h1234567890abcdefE"));
    RE_CHECK(strcmp(out.p, "std::io::stdio::_print::h1234567890abcdef") == 0);
    // A member function template renders its arguments on the template name,
    // and a template parameter whose type is unknown says so rather than failing.
    RE_CHECK(DEMANGLE("_ZN3foo3barIiEEvT_"));
    RE_CHECK(strcmp(out.p, "foo::bar<int>(auto)") == 0);
    // A substitution reference resolves through the pool.
    RE_CHECK(DEMANGLE("_ZN1a1bES_"));
    RE_CHECK(strcmp(out.p, "a::b()") == 0);
    // Malformed input is refused rather than guessed at.
    RE_CHECK(!DEMANGLE("_ZN3fo"));
    RE_CHECK(!DEMANGLE("not_mangled"));
    RE_CHECK(!DEMANGLE("_ZN3foo3bar"));
    RE_CHECK(re_demangle_msvc(&a, "?func@@YAXXZ", strlen("?func@@YAXXZ"), &out));
    RE_CHECK(strcmp(out.p, "func()") == 0);
    RE_CHECK(re_demangle_msvc(&a, "?f@@YAHH@Z", strlen("?f@@YAHH@Z"), &out));
    RE_CHECK(strcmp(out.p, "f(int)") == 0);
#undef DEMANGLE
    re_arena_free(&a);
    test_demangle_msvc();
    test_demangle_rust();
    test_demangle_rust_tuple();
}

// Rust symbols. Every mangled name here is real: the simple ones are the symbols a real
// rustc emitted for the functions of a test crate, which is what makes them checkable
// against the source rather than against a guess. The expected text is what a reader
// sees, so the crate and impl disambiguators are absent: they name an instance of a
// crate rather than a function.
static void test_demangle_rust(void) {
    // The legacy Rust spelling: an Itanium name whose last component is the compiler's
    // own hash. Rust does not print that component, which is why the dispatcher strips it
    // and the Itanium reader keeps it.
    static const char *const kLegacy = "_ZN3std2io5stdio6_print17h1234567890abcdefE";
    re_arena_t a;
    re_str_t out;
    static const struct {
        const char *sym;
        const char *want;
    } kCases[] = {
        {"_RNvCsern1Y9cEla9_4rlib6render", "rlib::render"},
        {"_RNvCsern1Y9cEla9_4rlib7sum_vec", "rlib::sum_vec"},
        // An inherent impl: the self type is written in angle brackets and the impl
        // path is not written at all, which is the shape the compiler book recommends.
        {"_RNvMsr_NtCs3ssYzQotkvD_3std4pathNtB5_7PathBuf3newCs15kBYyAo9fc_7mycrate",
         "<std::path::PathBuf>::new"},
        // A trait impl, the book's other worked example.
        {"_RNvXCs15kBYyAo9fc_7mycrateNtB2_7ExampleNtB2_5Trait3foo",
         "<mycrate::Example as mycrate::Trait>::foo"},
        // Generic arguments, a tuple type, and two backrefs: the second mention of a
        // path is a byte offset rather than a second copy of it.
        {"_RINvNtCs55qC6OcLGgs_4core3ptr9drop_glueINtNtCs8oYkXk2gzQW_5alloc3vec3VecNtNtBG_"
         "6string6StringEECsiYmzjmTrTwQ_4rgen",
         "core::ptr::drop_glue::<alloc::vec::Vec<alloc::string::String>>"},
        // A closure under a generic function, with the enclosing argument list and an
        // empty identifier whose disambiguator is what names it.
        {"_RNCINvMs6_NtCsfNFD5h9On6T_9hashbrown3rawINtB8_8RawTableTNtNtCs8oYkXk2gzQW_5alloc"
         "6string6StringmEE14reserve_rehashNCINvNtBa_3map11make_hasherBS_mNtNtNtCslFVcyoAu48q_"
         "3std4hash6random11RandomStateE0E0CsiYmzjmTrTwQ_4rgen",
         "<hashbrown::raw::RawTable<(alloc::string::String, u32)>>::reserve_rehash::<"
         "hashbrown::map::make_hasher::<alloc::string::String, u32, "
         "std::hash::random::RandomState>::{closure#0}>::{closure#0}"},
    };
    re_arena_init(&a, 0);
    RE_CHECK_EQ_U(re_mangle_kind(kCases[0].sym, strlen(kCases[0].sym)), RE_MANGLE_RUST);
    // The legacy spelling is Itanium shaped, and it is the trailing hash that says it came
    // from Rust: a C++ name never ends that way, so the two can be told apart.
    RE_CHECK_EQ_U(re_mangle_kind(kLegacy, strlen(kLegacy)), RE_MANGLE_RUST);
    RE_CHECK_EQ_U(re_mangle_kind("_ZN3foo3barEv", 13), RE_MANGLE_ITANIUM);
    RE_CHECK_EQ_STR(re_mangle_name(RE_MANGLE_RUST), "rust");
    RE_CHECK_EQ_STR(re_mangle_name(RE_MANGLE_ITANIUM), "itanium");
    for (size_t i = 0; i < sizeof(kCases) / sizeof(kCases[0]); i++) {
        RE_CHECK(re_demangle(&a, kCases[i].sym, strlen(kCases[i].sym), &out));
        RE_CHECK_EQ_STR(out.p, kCases[i].want);
    }
    // The dispatcher drops the legacy hash, which the Itanium reader keeps: the hash is a
    // component of the name to a C++ demangler and the compiler's own disambiguator to
    // Rust, and Rust does not print it.
    RE_CHECK(re_demangle(&a, kLegacy, strlen(kLegacy), &out));
    RE_CHECK_EQ_STR(out.p, "std::io::stdio::_print");
    // A punycode identifier is refused rather than printed as its own encoding, and a
    // symbol that stops in the middle of a name is refused rather than completed.
    RE_CHECK(!re_demangle(&a, "_RNvCsern1Y9cEla9_4rlibu5gdel", 27, &out));
    RE_CHECK(!re_demangle(&a, "_RNvCsern1Y9cEla9_4rlib6rend", 26, &out));
    re_arena_free(&a);
}

// A tuple of one field keeps its trailing comma: the same text without it is a
// parenthesized type, and in Rust that is a different type rather than a shorter way of
// writing the same one. The symbol is real, and it is where the corpus first showed the
// difference.
static void test_demangle_rust_tuple(void) {
    static const char *const kSym =
        "_RNvYNCINvMs6_NtCsfNFD5h9On6T_9hashbrown3rawINtBb_8RawTableTNtNtCs8oYkXk2gzQW_5alloc6strin"
        "g6StringmEE14reserve_rehashNCINvNtBd_3map11make_hasherBV_mNtNtNtCslFVcyoAu48q_3std4hash6ra"
        "ndom11RandomStateE0Es_0INtNtNtCs55qC6OcLGgs_4core3ops8function6FnOnceTOhEE9call_onceCsiYmz"
        "jmTrTwQ_4rgen";
    static const char *const kWant =
        "<<hashbrown::raw::RawTable<(alloc::string::String, u32)>>::reserve_rehash::<hashbrown::map"
        "::make_hasher::<alloc::string::String, u32, std::hash::random::RandomState>::{closure#0}>:"
        ":{closure#1} as core::ops::function::FnOnce<(*mut u8,)>>::call_once";
    re_arena_t a;
    re_str_t out;
    re_arena_init(&a, 0);
    RE_CHECK(re_demangle(&a, kSym, strlen(kSym), &out));
    RE_CHECK_EQ_STR(out.p, kWant);
    re_arena_free(&a);
}

// YAA is a three letter calling convention or the two letter YA followed by A, which
// opens a reference to the return type, and nothing in the name says which. The first
// reading was committed to, so these two either came out with a signature that read
// correctly and was wrong, or came out as nothing at all. Both symbols are real
// exports of a shipped binary, so this is not a synthetic case.
static void test_demangle_msvc(void) {
    re_arena_t a;
    re_str_t out;
    re_arena_init(&a, 0);
    static const char *const kAmb[] = {
        "?generic_category@system@boost@@YAAEBVerror_category@12@XZ",
        "?system_category@system@boost@@YAAEBVerror_category@12@XZ",
    };
    static const char *const kWant[] = {"boost::system::generic_category()",
                                        "boost::system::system_category()"};
    for (size_t i = 0; i < 2; i++) {
        RE_CHECK(re_demangle_msvc(&a, kAmb[i], strlen(kAmb[i]), &out));
        RE_CHECK_EQ_STR(out.p, kWant[i]);
        // And again, because the reading that succeeds is chosen by trying, and the
        // ones before it have already written into the buffer this reuses.
        RE_CHECK(re_demangle_msvc(&a, kAmb[i], strlen(kAmb[i]), &out));
        RE_CHECK_EQ_STR(out.p, kWant[i]);
    }
    // Where the first convention candidate consumes the whole name it still wins, so
    // the backtracking did not simply come to prefer the longer code.
    RE_CHECK(re_demangle_msvc(&a, "?func@@YAXXZ", 12, &out));
    RE_CHECK_EQ_STR(out.p, "func()");
    re_arena_free(&a);
}

static void test_entropy(void) {
    // Uniform data is maximal, a single repeated byte is zero.
    uint8_t zero[512];
    for (int i = 0; i < 512; i++)
        zero[i] = 0;
    re_span_t z = re_span(zero, 512);
    RE_CHECK(re_entropy(z) < 0.0001);
    size_t counts[2] = {256, 256};
    RE_CHECK(re_entropy_of_counts(counts, 2) > 0.999 && re_entropy_of_counts(counts, 2) < 1.001);
    size_t empty[2] = {0, 0};
    RE_CHECK_EQ_U((uint64_t)re_entropy_of_counts(empty, 2), 0);
    RE_CHECK_EQ_U((uint64_t)re_entropy(re_span_none()), 0);
}

// RTTI descriptors are class names, not function symbols. Reading them as symbols
// left every C++ class reported under its raw mangling.
static void test_rtti_names(void) {
    re_arena_t a;
    re_str_t out;
    re_arena_init(&a, 0);
#define RTTI(sym) re_demangle_rtti(&a, (sym), strlen(sym), &out)
    RE_CHECK(RTTI(".?AVProbe@@"));
    RE_CHECK_EQ_STR(out.p, "Probe");
    RE_CHECK(RTTI(".?AUplain_struct@@"));
    RE_CHECK_EQ_STR(out.p, "plain_struct");
    RE_CHECK(RTTI(".?AWan_enum@@"));
    RE_CHECK_EQ_STR(out.p, "an_enum");
    // @@ separates scopes and has to read as ::, or a qualified name comes out as the
    // mangling it was meant to replace.
    RE_CHECK(RTTI(".?AVstd@@vector@@"));
    RE_CHECK_EQ_STR(out.p, "std::vector");
    // A template's inner text is demangled when it is a symbol, and kept when it is not.
    RE_CHECK(RTTI(".?AVfoo@H@1@YAXZ@@"));
    RE_CHECK_EQ_STR(out.p, "foo@H@1@YAXZ");
    RE_CHECK(RTTI(".?AV?func@@YAXXZ@@"));
    RE_CHECK_EQ_STR(out.p, "func()");
    // Refused: not a descriptor, no closing scope, or a base-class descriptor kind.
    RE_CHECK(!RTTI("main"));
    RE_CHECK(!RTTI(".?AVno_closing@@x"));
    RE_CHECK(!RTTI(".?BAa_base_class_descriptor@@"));
    RE_CHECK(!RTTI(".?AV"));
    RE_CHECK(re_rtti_kind(".?AVProbe@@", strlen(".?AVProbe@@")));
    RE_CHECK(!re_rtti_kind("?func@@YAXXZ", strlen("?func@@YAXXZ")));
#undef RTTI
    re_arena_free(&a);
}

static void test_string_runs(void) {
    re_arena_t a;
    re_str_page_t page;
    re_str_around_t ar;
    re_rx_t *rx;
    uint8_t ascii[18];
    uint8_t wide[40];
    const re_str_hit_t *h;
    size_t i;
    re_arena_init(&a, 0);
    memset(ascii, 0, sizeof(ascii));
    memcpy(ascii, "alpha", 5);
    memcpy(ascii + 6, "betaX", 5);
    memcpy(ascii + 12, "gamma", 5);
    rx = re_rx_compile(&a, "gamma", NULL, NULL);
    re_strings_collect(re_span(ascii, 17), 4, rx, 0, 1, &a, &page);
    RE_CHECK_EQ_U(page.total, 1);
    RE_CHECK_EQ_U(RE_VEC_LEN(&page.hits), 1);
    h = RE_VEC_PTR(&page.hits, re_str_hit_t, 0);
    RE_CHECK_EQ_STR(h->text.p, "gamma");
    re_str_around(re_span(ascii, 17), 6, false, 4, 1, &a, &ar);
    RE_CHECK(ar.found);
    RE_CHECK_EQ_STR(ar.run.text.p, "betaX");
    RE_CHECK_EQ_U(RE_VEC_LEN(&ar.before), 1);
    RE_CHECK_EQ_U(RE_VEC_LEN(&ar.after), 1);
    h = RE_VEC_PTR(&ar.before, re_str_hit_t, 0);
    RE_CHECK_EQ_STR(h->text.p, "alpha");
    h = RE_VEC_PTR(&ar.after, re_str_hit_t, 0);
    RE_CHECK_EQ_STR(h->text.p, "gamma");
    memset(wide, 0, sizeof(wide));
    memcpy(wide, "AAAA", 4);
    for (i = 0; i < 4; i++)
        wide[6 + i * 2] = (uint8_t) "JUMP"[i];
    for (i = 0; i < 5; i++)
        wide[16 + i * 2] = (uint8_t) "HELLO"[i];
    for (i = 0; i < 5; i++)
        wide[28 + i * 2] = (uint8_t) "WORLD"[i];
    re_str_around(re_span(wide, 38), 18, true, 4, 1, &a, &ar);
    RE_CHECK(ar.found);
    RE_CHECK(ar.run.wide);
    RE_CHECK_EQ_STR(ar.run.text.p, "HELLO");
    h = RE_VEC_PTR(&ar.before, re_str_hit_t, 0);
    RE_CHECK(h->wide);
    RE_CHECK_EQ_STR(h->text.p, "JUMP");
    h = RE_VEC_PTR(&ar.after, re_str_hit_t, 0);
    RE_CHECK_EQ_STR(h->text.p, "WORLD");
    re_arena_free(&a);
}

int re_test_features(void) {
    test_time();
    test_search();
    test_demangle();
    test_rtti_names();
    test_entropy();
    test_string_runs();
    return 0;
}
