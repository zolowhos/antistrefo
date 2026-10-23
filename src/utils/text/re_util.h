// re_util.h - aggregator that pulls in the whole utility surface in one include.
// Module: util (C11).
// Owns: nothing. Convenience only, and the list scripts/check.py diffs against.
// Depends: every other re_util header. Core features must include what they use.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
// Only src/cli and src/mcp include this. A core feature that includes the
// aggregator pays for every utility it does not use, which is exactly the kind
// of accidental coupling the layering rules exist to prevent.
#include "utils/algo/re_crc.h"
#include "utils/algo/re_hash.h"
#include "utils/algo/re_regex.h"
#include "utils/algo/re_sort.h"
#include "utils/json/re_jr.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_bits.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_map.h"
#include "utils/mem/re_set.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_entropy.h"
#include "utils/sys/re_err.h"
#include "utils/sys/re_fsave.h"
#include "utils/sys/re_log.h"
#include "utils/sys/re_path.h"
#include "utils/sys/re_thread.h"
#include "utils/sys/re_time.h"
#include "utils/text/re_fmt.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"
#include "utils/text/re_text.h"
#include "utils/tui/re_console.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "utils/tui/re_syntax.h"
#include "utils/tui/re_tui.h"
#include "utils/tui/re_ui.h"
#ifdef __cplusplus
}
#endif
