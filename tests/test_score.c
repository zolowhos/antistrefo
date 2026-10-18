// test_score.c - the quality scoreboard over the hand built PE fixture.
// Module: test (C11).
// Owns: the scoreboard's numbers and the invariants between them.
// Depends: re_core through the public headers, driven through re_analysis_open so
//           the measured path is the one the analyze command runs.
#include "re_test.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "features/analysis/re_analyze.h"

#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

// The composite with no evidence at all is zero, not a crash and not a nan.
static void check_composite_bounds(void) {
    re_score_t s;
    memset(&s, 0, sizeof(s));
    RE_CHECK_EQ_U(re_score_composite(&s) == 0.0, 1);
    s.n_insns = 10;
    s.n_lowered = 3;
    // One axis with a denominator is that axis alone, scaled to a percentage.
    RE_CHECK_EQ_U(re_score_composite(&s) > 29.9 && re_score_composite(&s) < 30.1, 1);
}

// The axes on the real fixture. The image states one RUNTIME_FUNCTION at the start
// of .text, the walk recovers the functions the bytes hold, and every instruction
// in the fixture is one the lowering covers, so each axis has a floor that is a
// fact about the fixture rather than a tuning choice.
static void check_score_axes(void) {
    static const char kTmp[] = "re_test_score_fixture.sys";
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_analysis_t an;
    FILE *fh;
    build_pe(img);
    fh = fopen(kTmp, "wb");
    RE_CHECK(fh != NULL);
    if (!fh)
        return;
    fwrite(img, 1, sizeof(img), fh);
    fclose(fh);
    re_arena_init(&a, 1u << 20);
    RE_CHECK(re_analysis_open(&an, &a, kTmp));
    RE_CHECK(re_analysis_run_all(&an));
    RE_CHECK(an.has_code);
    // The score pass ran and left a record behind.
    const re_pass_stat_t *sc = re_analysis_pass(&an, RE_PASS_SCORE);
    RE_CHECK(sc != NULL && sc->ran);
    RE_CHECK(an.score.n_funcs > 0);
    // The exception table states function begins in .text, so at least one entry
    // must be matched by the walk, and every stated entry must be counted in the
    // denominator. The fixture writes two RUNTIME_FUNCTIONs.
    RE_CHECK_EQ_U(an.score.n_pdata, 2);
    RE_CHECK(an.score.n_pdata_hit >= 1);
    // The fixture branches, so the graph has edges and they all resolve.
    RE_CHECK(an.score.n_edges > 0);
    RE_CHECK_EQ_U(an.score.n_edges, an.score.n_edges_ok);
    // Most instructions in the fixture lower: cmp, je, mov, jmp, ret, sub. The
    // stack pushes and the pop are not in the modelled set yet, so the floor is
    // three quarters until the stack tranche of the lowering lands, at which
    // point this becomes exact equality on purpose.
    RE_CHECK(an.score.n_insns >= 10);
    RE_CHECK(an.score.n_lowered * 4 >= an.score.n_insns * 3);
    // No calls and no indirect transfers in the fixture, so those axes are
    // absent from the composite rather than scored as zero.
    RE_CHECK_EQ_U(an.score.n_calls, 0);
    RE_CHECK(an.score.score > 50.0);
    RE_CHECK(an.score.score <= 100.0);
    re_analysis_close(&an);
    re_arena_free(&a);
    remove(kTmp);
}

int main(void) {
    check_composite_bounds();
    check_score_axes();
    return re_test_report("score");
}
