// test_utils.c - verifies the utility layer against published test vectors.
// Module: test (C11).
// Owns: correctness checks for arena, string, container, hash, crc and regex code.
// Depends: re_utils only. Prints to stdout, which is fine for a test binary.
#include "features/data/re_search.h"
#include "features/lib/re_demangle.h"
#include "utils/sys/re_entropy.h"
#include "utils/sys/re_time.h"
#include "utils/text/re_util.h"
#include "re_test.h"

#include <string.h>

static void test_bits(void) {
    RE_CHECK_EQ_U(re_bits_popcount(0), 0);
    RE_CHECK_EQ_U(re_bits_popcount(0xffffffffffffffffULL), 64);
    RE_CHECK_EQ_U(re_bits_popcount(0x8000000000000000ULL), 1);
    RE_CHECK_EQ_U(re_bits_ctz64(8), 3);
    RE_CHECK_EQ_U(re_bits_clz64(1), 63);
    RE_CHECK_EQ_U(re_bits_rotr64(re_bits_rotl64(0x123456789abcdef0ULL, 16), 16),
                  0x123456789abcdef0ULL);
    RE_CHECK_EQ_HEX(re_bswap32(0x11223344u), 0x44332211u);
    RE_CHECK_EQ_HEX(re_bswap16(0x1234u), 0x3412u);
    RE_CHECK(re_align_up(5, 8) == 8);
    RE_CHECK(re_align_up(8, 8) == 8);
    RE_CHECK(re_bits_is_pow2(64));
    RE_CHECK(!re_bits_is_pow2(63));
}

static void test_hex(void) {
    const uint8_t data[4] = {0xde, 0xad, 0xbe, 0xef};
    char out[16];
    re_hex_encode(out, data, 4);
    RE_CHECK(strcmp(out, "deadbeef") == 0);
    re_hex_encode_upper(out, data, 4);
    RE_CHECK(strcmp(out, "DEADBEEF") == 0);
    uint8_t back[4];
    size_t n = 0;
    RE_CHECK(re_hex_decode(back, sizeof(back), "deadbeef", 8, &n, false));
    RE_CHECK_EQ_U(n, 4);
    RE_CHECK(memcmp(back, data, 4) == 0);
    RE_CHECK(!re_hex_decode(back, sizeof(back), "deadbeeg", 8, &n, false));
    uint8_t seps[4];
    RE_CHECK(re_hex_decode(seps, sizeof(seps), "de:ad:be:ef", 11, &n, true));
    RE_CHECK_EQ_U(n, 4);
    RE_CHECK_EQ_U(re_hex_run_len("0x1234zz", 8), 4);
    RE_CHECK_EQ_U(re_hex_run_len("1234", 4), 4);
    RE_CHECK_EQ_U(re_hex_run_len("zz", 2), 0);
}

static void test_arena(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    void *first = re_arena_alloc(&a, 24);
    RE_CHECK(first != NULL);
    RE_CHECK(((uintptr_t)first % RE_ARENA_ALIGN) == 0);
    memset(first, 0xab, 24);
    char *s = re_arena_strdup(&a, "hello arena");
    RE_CHECK(s && strcmp(s, "hello arena") == 0);
    char *t = re_arena_strndup(&a, s, 5);
    RE_CHECK(t && strcmp(t, "hello") == 0);
    size_t total = 0;
    for (int i = 0; i < 5000; i++) {
        int *p = (int *)re_arena_alloc(&a, sizeof(int));
        if (!p)
            break;
        *p = i;
        total += (size_t)*p;
    }
    RE_CHECK_EQ_U(total, 4999u * 5000u / 2u);
    re_arena_reset(&a);
    RE_CHECK_EQ_U(a.total, 0);
    char *again = re_arena_strdup(&a, "after reset");
    RE_CHECK(again && strcmp(again, "after reset") == 0);
    re_arena_free(&a);
    RE_CHECK(a.head == NULL);
}

static void test_str(void) {
    re_str_t a = re_str("Hello, World");
    RE_CHECK_EQ_U(a.n, 12);
    RE_CHECK(re_str_eq_cstr(a, "Hello, World"));
    RE_CHECK(re_str_starts_cstr(a, "Hello"));
    RE_CHECK(re_str_ends_cstr(a, "World"));
    RE_CHECK(re_str_istarts_cstr(a, "hello"));
    RE_CHECK(re_str_icmp(a, re_str("HELLO, WORLD")) == 0);
    RE_CHECK(re_str_ieq_cstr(a, "hello, world"));
    long at = re_str_find_cstr(a, "World", 0);
    RE_CHECK_EQ_U((size_t)at, 7);
    RE_CHECK(re_str_find_cstr(a, "Nope", 0) == -1);
    RE_CHECK_EQ_U((size_t)re_str_rfind_cstr(a, "l"), 10);
    re_str_t tr = re_str_trim(re_str("  padded \t"));
    RE_CHECK(re_str_eq_cstr(tr, "padded"));
    RE_CHECK(re_str_is_printable(re_str("all good!")));
    RE_CHECK(!re_str_is_printable(re_strn("bad\x01\x02", 5)));
    RE_CHECK_EQ_U(re_str_rfind_char(re_strn("a/b/c", 5), '/', 5), 3);
}

static void test_strbuf(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_strbuf_t b;
    re_strbuf_init(&b, &a);
    RE_CHECK(re_strbuf_puts(&b, "addr="));
    RE_CHECK(re_strbuf_put_hex64(&b, 0x140001000ULL, 16));
    RE_CHECK(re_strbuf_putc(&b, ' '));
    RE_CHECK(re_strbuf_put_u64(&b, 1234567890123ULL));
    RE_CHECK(strcmp(b.p, "addr=0000000140001000 1234567890123") == 0);
    re_strbuf_clear(&b);
    RE_CHECK(re_strbuf_appendf(&b, "%s=%d, %.2f", "n", -42, 1.5));
    RE_CHECK(strcmp(b.p, "n=-42, 1.50") == 0);
    re_strbuf_clear(&b);
    RE_CHECK(re_strbuf_appendf(&b, "%0900d", 7));
    RE_CHECK_EQ_U(b.len, 900);
    const uint8_t raw[3] = {0x01, 0xab, 0xff};
    re_strbuf_clear(&b);
    RE_CHECK(re_strbuf_put_hex(&b, raw, 3));
    RE_CHECK(strcmp(b.p, "01abff") == 0);
    re_arena_free(&a);
}

static int cmp_int(const void *x, const void *y, void *ctx) {
    (void)ctx;
    int a = *(const int *)x;
    int b = *(const int *)y;
    return (a > b) - (a < b);
}

static void test_vec_and_sort(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_vec_t v;
    re_vec_init(&v, sizeof(int));
    RE_CHECK_EQ_U(RE_VEC_LEN(&v), 0);
    for (int i = 0; i < 1000; i++) {
        int val = i * 7 % 1013;
        RE_CHECK(RE_VEC_PUSH(&v, &a, val));
    }
    RE_CHECK_EQ_U(RE_VEC_LEN(&v), 1000);
    re_vec_sort(&v, cmp_int, NULL);
    for (size_t i = 1; i < RE_VEC_LEN(&v); i++) {
        int prev = RE_VEC_AT(&v, int, i - 1);
        int cur = RE_VEC_AT(&v, int, i);
        if (prev > cur) {
            RE_CHECK(0);
            break;
        }
    }
    re_vec_t empty;
    re_vec_init(&empty, sizeof(int));
    re_vec_sort(&empty, cmp_int, NULL);
    re_arena_free(&a);
}

static void test_map_and_set(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_map_t m;
    re_map_init(&m, &a, 0);
    for (int i = 0; i < 2000; i++) {
        char key[32];
        snprintf(key, sizeof(key), "sym_%d", i);
        // The map stores the pointer, so each value needs its own storage.
        int *slot = (int *)re_arena_alloc(&a, sizeof(int));
        *slot = i;
        RE_CHECK(re_map_put(&m, key, strlen(key), slot));
    }
    RE_CHECK_EQ_U(re_map_count(&m), 2000);
    for (int i = 0; i < 2000; i += 7) {
        char key[32];
        snprintf(key, sizeof(key), "sym_%d", i);
        const int *got = (const int *)re_map_get(&m, key, strlen(key));
        RE_CHECK(got && *got == i);
    }
    re_set_t s;
    re_set_init(&s, &a, 0);
    re_set_add(&s, "one", 3, (void *)1);
    re_set_add(&s, "two", 3, (void *)2);
    RE_CHECK(re_set_hass(&s, re_str("one")));
    RE_CHECK(!re_set_hass(&s, re_str("three")));
    RE_CHECK_EQ_U(re_set_count(&s), 2);
    re_arena_free(&a);
}

static void test_path(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    RE_CHECK(re_path_is_abs("/usr/bin"));
    RE_CHECK(re_path_is_abs("C:\\Windows"));
    RE_CHECK(!re_path_is_abs("rel/path"));
    RE_CHECK(strcmp(re_path_basename_ptr("/usr/bin/tool.exe"), "tool.exe") == 0);
    RE_CHECK(re_path_ext_is("/usr/bin/tool.exe", ".exe"));
    RE_CHECK(re_path_ext_is("/usr/bin/tool.ELF", ".elf"));
    RE_CHECK(!re_path_ext_is("/usr/bin/tool", ".exe"));
    RE_CHECK(!re_path_ext_is("/usr/bin.d/tool", ".d"));
    char *d = re_path_dirname(&a, "/usr/bin/tool.exe");
    RE_CHECK(d && strcmp(d, "/usr/bin") == 0);
    char *j = re_path_join(&a, "/usr/bin", "tool.exe");
    RE_CHECK(j && strcmp(j, "/usr/bin/tool.exe") == 0);
    char *n = re_path_normalize(&a, "/usr/./bin/../lib//x.so");
    RE_CHECK(n && strcmp(n, "/usr/lib/x.so") == 0);
    re_arena_free(&a);
}

static void test_crc_and_hash(void) {
    re_crc_init();
    RE_CHECK_EQ_HEX(re_crc32_ieee_final("123456789", 9), 0xcbf43926u);
    RE_CHECK_EQ_HEX(re_crc16_x25_final("123456789", 9), 0x906eu);
    uint8_t d5[RE_MD5_LEN];
    char hex[RE_MD5_LEN * 2 + 1];
    re_md5("", 0, d5);
    re_hex_encode(hex, d5, RE_MD5_LEN);
    RE_CHECK(strcmp(hex, "d41d8cd98f00b204e9800998ecf8427e") == 0);
    re_md5("abc", 3, d5);
    re_hex_encode(hex, d5, RE_MD5_LEN);
    RE_CHECK(strcmp(hex, "900150983cd24fb0d6963f7d28e17f72") == 0);
    re_md5("message digest", 14, d5);
    re_hex_encode(hex, d5, RE_MD5_LEN);
    RE_CHECK(strcmp(hex, "f96b697d7cb7938d525a2f31aaf161d0") == 0);
    uint8_t d6[RE_SHA256_LEN];
    char hex6[RE_SHA256_LEN * 2 + 1];
    re_sha256("", 0, d6);
    re_hex_encode(hex6, d6, RE_SHA256_LEN);
    RE_CHECK(strcmp(hex6, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    re_sha256("abc", 3, d6);
    re_hex_encode(hex6, d6, RE_SHA256_LEN);
    RE_CHECK(strcmp(hex6, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    const char *long56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    re_sha256(long56, strlen(long56), d6);
    re_hex_encode(hex6, d6, RE_SHA256_LEN);
    RE_CHECK(strcmp(hex6, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
    // Cross a 64 byte block boundary through the streaming API.
    re_sha256_t sc;
    re_sha256_init(&sc);
    re_sha256_update(&sc, "ab", 2);
    re_sha256_update(&sc, "c", 1);
    re_sha256_final(&sc, d6);
    re_hex_encode(hex6, d6, RE_SHA256_LEN);
    RE_CHECK(strcmp(hex6, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

static void test_regex(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_err_t err;
    err.code = RE_OK;
    re_str_t text = re_str("the quick brown fox jumps over the lazy dog 42 times");
    size_t s = 0;
    size_t e = 0;
    re_rx_t *lit = re_rx_compile(&a, "brown", NULL, &err);
    RE_CHECK(lit != NULL);
    RE_CHECK(re_rx_is_literal(lit, NULL, NULL));
    RE_CHECK(re_rx_search(lit, text, &s, &e));
    RE_CHECK_EQ_U(s, 10);
    RE_CHECK_EQ_U(e, 15);
    re_rx_t *dots = re_rx_compile(&a, "b.own", NULL, &err);
    RE_CHECK(dots != NULL);
    RE_CHECK(re_rx_search(dots, text, &s, &e));
    re_rx_t *anch = re_rx_compile(&a, "^the", NULL, &err);
    RE_CHECK(anch && re_rx_search(anch, text, &s, &e));
    RE_CHECK_EQ_U(s, 0);
    re_rx_t *digits = re_rx_compile(&a, "[0-9]+", NULL, &err);
    RE_CHECK(digits != NULL);
    RE_CHECK(re_rx_search(digits, text, &s, &e));
    RE_CHECK_EQ_U(s, 44);
    RE_CHECK_EQ_U(e, 46);
    re_rx_t *star = re_rx_compile(&a, "o*k", NULL, &err);
    RE_CHECK(star && re_rx_search(star, text, &s, &e));
    // A single result matcher gets this wrong: the short branch must fail first.
    re_rx_t *alt = re_rx_compile(&a, "(qui|quick)", NULL, &err);
    RE_CHECK(alt != NULL);
    RE_CHECK(re_rx_search(alt, text, &s, &e));
    RE_CHECK_EQ_U(s, 4);
    RE_CHECK_EQ_U(e, 9);
    re_rx_t *eol = re_rx_compile(&a, "times$", NULL, &err);
    RE_CHECK(eol != NULL);
    RE_CHECK(re_rx_search(eol, text, &s, &e));
    RE_CHECK_EQ_U(e, (size_t)text.n);
    re_rx_t *ci = re_rx_compile(&a, "BROWN", "i", &err);
    RE_CHECK(ci != NULL);
    RE_CHECK(re_rx_search(ci, text, &s, &e));
    re_rx_t *bad = re_rx_compile(&a, "a(b", NULL, &err);
    RE_CHECK(bad == NULL);
    RE_CHECK(err.code == RE_E_USAGE);
    re_arena_free(&a);
}

static void test_fmt(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_strbuf_t b;
    re_strbuf_init(&b, &a);
    RE_CHECK(re_fmt_put_i64(&b, -9223372036854775807LL - 1));
    RE_CHECK(strcmp(b.p, "-9223372036854775808") == 0);
    re_strbuf_clear(&b);
    RE_CHECK(re_fmt_put_base(&b, 255, 16));
    RE_CHECK(strcmp(b.p, "ff") == 0);
    re_strbuf_clear(&b);
    RE_CHECK(re_fmt_put_base(&b, 5, 2));
    RE_CHECK(strcmp(b.p, "101") == 0);
    re_strbuf_clear(&b);
    RE_CHECK(re_fmt_put_size(&b, 1536));
    RE_CHECK(strcmp(b.p, "1.5K") == 0);
    re_strbuf_clear(&b);
    RE_CHECK(re_fmt_put_pad(&b, re_str("7"), 4, true));
    RE_CHECK(strcmp(b.p, "   7") == 0);
    re_arena_free(&a);
}

static void test_err(void) {
    re_err_t e;
    RE_ERR_OK(&e);
    RE_CHECK(re_err_ok(&e));
    RE_ERR_SETF(&e, RE_E_MALFORMED, "bad field %d at %#x", 7, 0x40);
    RE_CHECK(e.code == RE_E_MALFORMED);
    RE_CHECK(strcmp(re_err_msg(&e), "bad field 7 at 0x40") == 0);
    RE_CHECK(re_err_exit_code(RE_E_USAGE) == 2);
    RE_CHECK(re_err_exit_code(RE_E_NOTBIN) == 3);
    RE_CHECK(re_err_exit_code(RE_E_MALFORMED) == 4);
    RE_CHECK(re_err_exit_code(RE_E_UNSUPPORTED) == 5);
    RE_CHECK(re_err_exit_code(RE_E_IO) == 6);
    RE_CHECK(re_err_exit_code(RE_OK) == 0);
    RE_CHECK(strcmp(re_err_str(RE_E_RANGE), "read out of bounds") == 0);
}

static void test_json(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_jw_t w;
    re_jw_init(&w, &a);
    re_jw_obj(&w);
    re_jw_kcstr(&w, "k", "v");
    re_jw_ku64(&w, "n", 42);
    re_jw_kbool(&w, "b", true);
    re_jw_knull(&w, "z");
    re_jw_obj_end(&w);
    RE_CHECK(strcmp(w.buf.p, "{\"k\":\"v\",\"n\":42,\"b\":true,\"z\":null}") == 0);
    re_jw_init(&w, &a);
    re_jw_obj(&w);
    re_jw_key(&w, "arr");
    re_jw_arr(&w);
    for (int i = 0; i < 5; i++) {
        re_jw_obj(&w);
        re_jw_ku64(&w, "i", (uint64_t)i);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_obj_end(&w);
    RE_CHECK(re_jw_ok(&w));
    RE_CHECK(strcmp(w.buf.p, "{\"arr\":[{\"i\":0},{\"i\":1},{\"i\":2},{\"i\":3},{\"i\":4}]}") == 0);
    // A string carrying raw NULs must be escaped, or the response is not JSON.
    re_jw_init(&w, &a);
    re_jw_obj(&w);
    re_jw_kstr(&w, "raw", re_strn("\\\0D\0e", 5));
    re_jw_obj_end(&w);
    RE_CHECK(strcmp(w.buf.p, "{\"raw\":\"\\\\\\u0000D\\u0000e\"}") == 0);
    for (size_t i = 0; i < w.buf.len; i++)
        RE_CHECK(w.buf.p[i] != '\0' || i == w.buf.len);
    // Long output forces several reallocations, which is where a length bug shows.
    re_jw_init(&w, &a);
    re_jw_obj(&w);
    for (int i = 0; i < 4000; i++) {
        re_jw_key(&w, "key");
        re_jw_u64(&w, (uint64_t)i);
    }
    re_jw_obj_end(&w);
    RE_CHECK(re_jw_ok(&w));
    size_t expect = 2;
    for (int i = 0; i < 4000; i++) {
        expect += 6 + (size_t)snprintf(NULL, 0, "%llu", (unsigned long long)i);
        if (i + 1 < 4000)
            expect += 1; // comma between members
    }
    RE_CHECK_EQ_U(w.buf.len, expect);
    for (size_t i = 0; i < w.buf.len; i++)
        RE_CHECK(w.buf.p[i] != '\0');
    re_arena_free(&a);
}

static void test_str_split_join(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_vec_t parts = re_str_split(&a, re_str("a,bb,,ccc"), ',');
    RE_CHECK_EQ_U(RE_VEC_LEN(&parts), 4);
    RE_CHECK(re_str_eq_cstr(RE_VEC_AT(&parts, re_str_t, 0), "a"));
    RE_CHECK(re_str_eq_cstr(RE_VEC_AT(&parts, re_str_t, 2), ""));
    char *joined = re_str_join(&a, &parts, ";");
    RE_CHECK(joined && strcmp(joined, "a;bb;;ccc") == 0);
    re_arena_free(&a);
}

// The step two feature checks live in test_features.c and share these counters.
int re_test_features(void);

int re_test_count = 0;
int re_test_fail = 0;

// The MSVC demangler against symbols with known right answers. Content, not counts:
// a demangler that rejects everything passes a count-only check, and one that answers
// wrongly is worse than one that refuses.
static void check_demangle(void) {
    static const struct {
        const char *sym;
        const char *want;
    } kCases[] = {
        {"?foo@@YAXXZ", "foo()"},
        {"?f@@YAXH@Z", "f(int)"},
        {"?bar@@YAXPEBD@Z", "bar(char const *)"},
        {"?g@@YAXPEAVfoo@@@Z", "g(foo const *)"},
    };
    for (size_t i = 0; i < sizeof(kCases) / sizeof(kCases[0]); i++) {
        re_arena_t a;
        re_str_t out = re_str("");
        bool ok;
        re_arena_init(&a, 4096);
        ok = re_demangle_msvc(&a, kCases[i].sym, strlen(kCases[i].sym), &out);
        RE_CHECK(ok);
        RE_CHECK(re_str_eq_cstr(out, kCases[i].want));
        re_arena_free(&a);
    }
}

int main(void) {
    test_bits();
    test_hex();
    test_arena();
    test_str();
    test_strbuf();
    test_vec_and_sort();
    test_map_and_set();
    test_path();
    test_crc_and_hash();
    test_regex();
    test_fmt();
    test_err();
    test_json();
    test_str_split_join();
    check_demangle();
    re_test_features();
    return re_test_report("all");
}
