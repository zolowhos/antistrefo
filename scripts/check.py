#!/usr/bin/env python3
# check.py - enforces the banner, line caps, whitespace and layering rules.
# Module: tool (Python 3).
# Owns: the pre-commit gate, exits nonzero on any violation, repairs the mechanical ones only.
# Depends: stdlib only. No network. Rules are specified in .rules/rules.md.

import argparse
import os
import re
import sys

SKIP_DIRS = {".git", ".vs", "build", "out", "__pycache__", ".cache", "Tools",
             ".freebuff", ".opencode"}  # local agent tooling, like .vs
MAX_LINES = 500
MAX_FOLDER_FILES = 15
MAX_FUNC_LINES = 60
MAX_NESTING = 4
BANNER_LINES = 4

# Files with a closed external schema or legal text cannot carry a banner.
BANNER_EXEMPT = {"LICENSE", "CMakePresets.json"}
# Legal texts may legitimately contain trailing spaces.
TRAILING_WS_EXEMPT = {"LICENSE"}
# Non ASCII is fine in prose, never in code.
ASCII_EXEMPT_SUFFIX = {".md"}
# Only real code is held to the layering rules. Prose and configs mention printf
# and malloc constantly, in tables, and flagging those is pure noise.
CODE_SUFFIX = {".c", ".h", ".cpp", ".hpp", ".cc"}
# Internal headers that must stay out of the aggregator on purpose.
PRIVATE_UTILS = {"re_regex_priv.h", "re_util.h"}

COMMENT_CHAR = {
    ".c": "//", ".h": "//", ".cpp": "//", ".hpp": "//", ".cc": "//",
    ".py": "#", ".md": "#", ".txt": "#", ".cmake": "#", ".ps1": "#",
    ".yml": "#", ".yaml": "#", ".toml": "#", ".json": "#", ".rules": "#",
    ".gitignore": "#", ".editorconfig": "#", ".clang-format": "#", ".clang-tidy": "#",
}
KNOWN_SUFFIX = set(COMMENT_CHAR)

# Rule 6: allocation is only legal inside the arena and the utility sources.
ALLOC_RE = re.compile(r"\b(malloc|calloc|realloc|free|_aligned_malloc)\s*\(")
STRDUP_RE = re.compile(r"\bstrdup\s*\(")
# Rule 8: unbounded or unsafe libc string handling. memcpy, memset and memcmp
# stay legal because every span in this project is already length checked.
LIBC_STR_RE = re.compile(r"\b(strlen|strcmp|strncmp|strcat|strcpy|strncpy|strtok|"
                         r"sprintf|vsprintf|gets|strdup)\s*\(")
# Rule 7: stdout is reserved for the JSON emitter and the text renderer.
STDOUT_RE = re.compile(r"(?<![\w.>])(printf|puts)\s*\(|fprintf\s*\(\s*stdout")
# Rule 0: the bit clearing loop is the classic hand rolled re_bits.
BITTRICK_RE = re.compile(r"&=\s*\w+\s*-\s*1\s*\)")

BANNER_MODULE_RE = re.compile(r"^Module:\s+\S+\s+\([^)]+\)\.\s*$")
BANNER_OWNS_RE = re.compile(r"^Owns:\s+\S")
BANNER_DEPS_RE = re.compile(r"^Depends:\s+\S")


class Report:
    def __init__(self):
        self.items = []
        self.fixed = 0

    def add(self, path, line, rule, msg, fixable=False):
        self.items.append((path, line, rule, msg, fixable))

    def count(self):
        return len(self.items)


def comment_char(path, name):
    if name in COMMENT_CHAR:
        return COMMENT_CHAR[name]
    for suf, ch in COMMENT_CHAR.items():
        if name.endswith(suf):
            return ch
    if name.startswith(".") and name.count(".") == 1:
        return "#"
    return "#"


def collect_files(root):
    out = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            p = os.path.join(base, f)
            name = f.lower()
            if name in BANNER_EXEMPT or name == "cmakelists.txt":
                suf = ".txt" if name == "cmakelists.txt" else os.path.splitext(name)[1]
            else:
                suf = os.path.splitext(name)[1]
            if suf not in KNOWN_SUFFIX and name not in COMMENT_CHAR:
                if not (name.startswith(".") and name.count(".") == 1):
                    continue
            out.append(p)
    return out


def check_whitespace(path, rel, text, rep, fix):
    """Normalize line endings, the final newline and trailing spaces.

    Returns the text to write back when fixing, otherwise the input unchanged.
    """
    fixed = False
    out = text
    if "\r\n" in out:
        if fix:
            out = out.replace("\r\n", "\n")
            fixed = True
            rep.fixed += 1
        else:
            rep.add(rel, 0, "rule5", "file contains CRLF line endings", True)
    if not out.endswith("\n"):
        if fix:
            out += "\n"
            fixed = True
            rep.fixed += 1
        else:
            rep.add(rel, 0, "rule5", "file does not end with a newline", True)
    if out.endswith("\n\n"):
        rep.add(rel, out.count("\n"), "rule5", "file ends with a blank line", True)
    name = os.path.basename(path)
    suffix = os.path.splitext(path)[1]
    if name not in TRAILING_WS_EXEMPT and suffix != ".md":
        lines = out.split("\n")
        changed = False
        for i, line in enumerate(lines):
            if line != line.rstrip():
                if fix:
                    lines[i] = line.rstrip()
                    changed = True
                else:
                    rep.add(rel, i + 1, "rule5", "trailing whitespace", True)
        if changed:
            out = "\n".join(lines)
            fixed = True
            rep.fixed += 1
    for i, line in enumerate(out.split("\n"), 1):
        if "\t" in line and suffix not in (".md", ".rules"):
            rep.add(rel, i, "rule5", "tab character in an indented file")
    if suffix not in ASCII_EXEMPT_SUFFIX:
        try:
            out.encode("ascii")
        except UnicodeEncodeError as e:
            rep.add(rel, 0, "rule4", f"non ASCII byte at offset {e.start}")
    return (out if fixed else text), fixed


def check_banner(path, rel, lines, rep):
    name = os.path.basename(path)
    if name in BANNER_EXEMPT:
        return
    ch = comment_char(path, name)
    # A shebang has to be the very first line, so a .py file shifts its banner.
    start = 0
    if lines and lines[0].startswith("#!"):
        start = 1
    banner = lines[start:start + BANNER_LINES]
    for i, line in enumerate(banner):
        if not line.startswith(ch):
            rep.add(rel, start + i + 1, "rule2",
                    f"banner line {i + 1} must start with '{ch}'")
    if len(banner) < BANNER_LINES:
        rep.add(rel, start + len(banner) + 1, "rule2",
                "file has fewer than 4 banner lines")
        return
    if name not in banner[0]:
        rep.add(rel, start + 1, "rule2", "banner line 1 must name the file")
    if not BANNER_MODULE_RE.match(banner[1][len(ch):].strip()):
        rep.add(rel, start + 2, "rule2", 'banner line 2 must read "Module: <name> (<lang>)."')
    if not BANNER_OWNS_RE.match(banner[2][len(ch):].strip()):
        rep.add(rel, start + 3, "rule2", 'banner line 3 must start with "Owns:"')
    if not BANNER_DEPS_RE.match(banner[3][len(ch):].strip()):
        rep.add(rel, start + 4, "rule2", 'banner line 4 must start with "Depends:"')


def strip_noise(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    # Drop preprocessor lines. The extern "C" guard opens a brace that would
    # otherwise swallow a whole header and look like one enormous function.
    text = re.sub(r"(?m)^\s*#.*$", " ", text)
    text = re.sub(r'"(\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(\\.|[^'\\])*'", "''", text)
    return text


TYPEDEF_RE = re.compile(r"^\s*(typedef|struct|union|enum)\b")


def check_functions(path, rel, text, rep):
    if os.path.splitext(path)[1] not in CODE_SUFFIX:
        return
    clean = strip_noise(text)
    lines = clean.split("\n")
    depth = 0
    start = 0
    maxdepth = 0
    for i, line in enumerate(lines, 1):
        opens = line.count("{")
        closes = line.count("}")
        if opens and depth == 0:
            # Only a function body counts. A struct, enum, union, typedef or a
            # brace initialiser also opens depth 0 and is not a function.
            prev = lines[i - 2] if i >= 2 else ""
            head = (prev + line).split("{")[0]
            if ")" not in head or TYPEDEF_RE.match(head) or "=" in head:
                start = 0
                depth += opens
                maxdepth = 0
                if depth <= 0:
                    depth = 0
                continue
            start = i
            maxdepth = 1
        elif opens:
            maxdepth = max(maxdepth, depth + opens)
        depth += opens - closes
        if depth <= 0 and start:
            body = i - start + 1
            if body > MAX_FUNC_LINES:
                rep.add(rel, start, "rule0",
                        f"function body is {body} lines, cap is {MAX_FUNC_LINES}")
            if maxdepth - 1 > MAX_NESTING:
                rep.add(rel, start, "rule0",
                        f"nesting depth {maxdepth - 1} exceeds cap {MAX_NESTING}")
            depth = 0
            start = 0


def check_layering(path, rel, text, rep):
    if os.path.splitext(path)[1] not in CODE_SUFFIX:
        return
    name = os.path.basename(path)
    is_util = "/utils/" in rel
    # Tests are held to format, size and structure, but they exist to call libc
    # and print, which is the very thing rules 7 and 8 forbid in the product.
    is_test = rel.startswith("tests/")
    allowed_stdout = name.startswith("re_jw") or name.startswith("re_text") or is_test
    for i, line in enumerate(text.split("\n"), 1):
        code = line.split("//")[0]
        if not is_util:
            if ALLOC_RE.search(code) or STRDUP_RE.search(code):
                rep.add(rel, i, "rule6", "allocation outside src/utils, use re_arena")
        if re.search(r"\brealloc\s*\(", code):
            rep.add(rel, i, "rule0", "realloc, use re_strbuf or re_vec")
        if not is_util and not is_test and LIBC_STR_RE.search(code):
            rep.add(rel, i, "rule8", "libc string call, use re_str or re_strbuf")
        if not allowed_stdout and STDOUT_RE.search(code):
            rep.add(rel, i, "rule7", "write to stdout outside re_jw or re_text")
        if BITTRICK_RE.search(code):
            rep.add(rel, i, "rule0", "hand rolled bit clear, use re_bits")


def check_pragma(path, rel, text, rep):
    if os.path.splitext(path)[1] not in (".h", ".hpp"):
        return
    n = len(re.findall(r"^#pragma once\s*$", text, flags=re.M))
    if n == 0:
        rep.add(rel, 0, "rule3", "header has no '#pragma once'")
    elif n > 1:
        rep.add(rel, 0, "rule3", "header has more than one '#pragma once'")


def check_util_catalog(root, rep):
    utils = os.path.join(root, "src", "utils")
    if not os.path.isdir(utils):
        return
    headers = sorted(f for f in os.listdir(utils) if f.endswith(".h"))
    agg = os.path.join(utils, "re_util.h")
    agg_text = open(agg, encoding="utf-8").read() if os.path.exists(agg) else ""
    cat_path = os.path.join(root, "docs", "util-catalog.md")
    cat_text = open(cat_path, encoding="utf-8").read() if os.path.exists(cat_path) else ""
    for h in headers:
        if h not in PRIVATE_UTILS:
            inc = f'#include "utils/{h}"'
            if inc not in agg_text:
                rep.add("src/utils/re_util.h", 0, "rule0",
                        f"{h} is missing from the aggregator, add {inc}")
        if h not in cat_text:
            rep.add("docs/util-catalog.md", 0, "rule0", f"{h} is not in the util catalog")


def check_folder_size(root, rep):
    """rule2: a folder over MAX_FOLDER_FILES must be divided into sub folders.

    Only src/ is checked. A limit that applied to the whole tree would fail on the
    build and .git directories, which say nothing about how the source is arranged.
    """
    src = os.path.join(root, "src")
    if not os.path.isdir(src):
        return
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if len(filenames) > MAX_FOLDER_FILES:
            rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
            rep.add(rel, 0, "rule2",
                    f"{len(filenames)} files, cap is {MAX_FOLDER_FILES}; divide it into "
                    "sub folders by category")


def main():
    ap = argparse.ArgumentParser(description="enforce the project rules")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--fix", action="store_true", help="repair mechanical violations")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    rep = Report()
    for path in collect_files(root):
        rel = os.path.relpath(path, root).replace("\\", "/")
        try:
            text = open(path, encoding="utf-8", newline="").read()
        except UnicodeDecodeError:
            rep.add(rel, 0, "rule4", "file is not valid UTF-8")
            continue
        new_text, changed = check_whitespace(path, rel, text, rep, args.fix)
        if args.fix and changed:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(new_text)
        check_banner(path, rel, new_text.split("\n"), rep)
        check_pragma(path, rel, text, rep)
        check_layering(path, rel, text, rep)
        check_functions(path, rel, text, rep)
        lines = new_text.split("\n")
        if len(lines) > MAX_LINES:
            rep.add(rel, len(lines), "rule1", f"{len(lines)} lines, cap is {MAX_LINES}")
    check_util_catalog(root, rep)
    check_folder_size(root, rep)
    if not args.quiet:
        for p, ln, rule, msg, _fixable in sorted(rep.items):
            where = f"{p}:{ln}" if ln else p
            print(f"{where}: {rule}  {msg}")
    if rep.count():
        print(f"\n{rep.count()} violation(s)")
        return 1
    print("all rules pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
