#!/usr/bin/env python3
# ida_mcp_shim.py - minimal ida-domain facade over antistrefo JSON CLI.
# Module: tool (Python 3).
# Owns: db object, capture of result/stdout/stderr for execute_python.
# Depends: stdlib + antistrefo executable in ANTISTREFO. No IDA, no network.
"""Compatible shapes only; not a copy of proprietary IDA code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from typing import Any


def _exe() -> str:
    path = os.environ.get("ANTISTREFO")
    if not path:
        raise RuntimeError("ANTISTREFO is not set")
    return path


def _ea(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0) if value else 0
    return int(value)


def _run_json(args: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        [_exe(), *args, "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "command failed")
    text = proc.stdout.strip()
    if not text:
        return {}
    return json.loads(text)


class _Func:
    def __init__(self, row: dict[str, Any], db: "Database") -> None:
        self._db = db
        self.start_ea = _ea(row.get("va") or row.get("ea"))
        if not self.start_ea:
            self.start_ea = _ea(row.get("rva"))
        self.size = _ea(row.get("size"))
        self.end_ea = self.start_ea + self.size
        self.name = row.get("name") or f"sub_{self.start_ea:X}"

    def decompile(self) -> str:
        data = _run_json(["decompile", self._db.path, f"0x{self.start_ea:x}"])
        return data.get("source") or data.get("text") or data.get("c") or json.dumps(data)


class _Functions:
    def __init__(self, db: "Database") -> None:
        self._db = db
        self._rows: list[dict[str, Any]] | None = None

    def _load(self) -> list[dict[str, Any]]:
        if self._rows is None:
            data = _run_json(["funcs", self._db.path])
            self._rows = list(data.get("funcs") or data.get("functions") or [])
        return self._rows

    def get_all(self) -> list[_Func]:
        return [_Func(r, self._db) for r in self._load()]

    def get_at(self, ea: int) -> _Func | None:
        for fn in self.get_all():
            if fn.start_ea <= int(ea) < (fn.end_ea or fn.start_ea + 1):
                return fn
        return None

    def __iter__(self):
        return iter(self.get_all())


class _String:
    def __init__(self, row: dict[str, Any]) -> None:
        self.address = _ea(row.get("va") or row.get("ea") or row.get("off"))
        self._text = row.get("text") or ""
        self.length = _ea(row.get("len")) or len(self._text)

    def __str__(self) -> str:
        return self._text


class _Strings:
    def __init__(self, db: "Database") -> None:
        self._db = db

    def __iter__(self):
        data = _run_json(["strings", self._db.path])
        for row in data.get("strings") or []:
            yield _String(row)


class _Segments:
    def __init__(self, db: "Database") -> None:
        self._db = db

    def get_all(self) -> list[dict[str, Any]]:
        data = _run_json(["sections", self._db.path])
        return list(data.get("sections") or data.get("segments") or [])


class _Xrefs:
    def __init__(self, db: "Database") -> None:
        self._db = db

    def to_ea(self, ea: int) -> list[dict[str, Any]]:
        data = _run_json(["xrefs", self._db.path, f"0x{int(ea):x}"])
        return list(data.get("xrefs") or data.get("to") or [])

    def from_ea(self, ea: int) -> list[dict[str, Any]]:
        data = _run_json(["xrefs", self._db.path, f"0x{int(ea):x}"])
        return list(data.get("from") or data.get("xrefs") or [])

    # ida-domain style aliases agents sometimes emit
    def to(self, ea: int) -> list[dict[str, Any]]:
        return self.to_ea(ea)

    def fro(self, ea: int) -> list[dict[str, Any]]:
        return self.from_ea(ea)


class _Entries:
    def __init__(self, db: "Database") -> None:
        self._db = db

    def get_all(self) -> list[dict[str, Any]]:
        data = _run_json(["exports", self._db.path])
        return list(data.get("exports") or data.get("entries") or [])


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self.functions = _Functions(self)
        self.strings = _Strings(self)
        self.segments = _Segments(self)
        self.xrefs = _Xrefs(self)
        self.entries = _Entries(self)

    def disasm(self, ea: int, length: int = 32) -> Any:
        return _run_json(["disasm", self.path, f"0x{int(ea):x}", "--len", str(int(length))])


class _Hexrays:
    @staticmethod
    def decompile(ea: int) -> str:
        db = _CURRENT_DB
        if db is None:
            raise RuntimeError("no database")
        fn = db.functions.get_at(int(ea))
        if fn is None:
            data = _run_json(["decompile", db.path, f"0x{int(ea):x}"])
            return data.get("source") or data.get("text") or json.dumps(data)
        return fn.decompile()


class _IdaDomain:
    Database = Database


_CURRENT_DB: Database | None = None


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, _Func):
        return {"start_ea": value.start_ea, "end_ea": value.end_ea, "name": value.name,
                "size": value.size}
    if isinstance(value, _String):
        return {"address": value.address, "length": value.length, "text": str(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
        return [_jsonable(v) for v in value]
    return repr(value)


def _exec_user(code: str, db: Database) -> Any:
    global _CURRENT_DB
    _CURRENT_DB = db
    g: dict[str, Any] = {
        "db": db,
        "ida_domain": _IdaDomain,
        "ida_hexrays": _Hexrays,
        "__name__": "__main__",
    }
    # Match ida-mcp: trailing expression value is returned; else run()/execute()/main().
    tree = compile(code, "<ida-mcp>", "exec")
    lines = [ln for ln in code.strip().splitlines() if ln.strip()]
    result = None
    if lines:
        try:
            last = compile(lines[-1], "<ida-mcp>", "eval")
            head = compile("\n".join(lines[:-1]) if len(lines) > 1 else "pass",
                           "<ida-mcp>", "exec")
            exec(head, g, g)
            result = eval(last, g, g)
            return result
        except SyntaxError:
            pass
    exec(tree, g, g)
    for name in ("run", "execute", "main"):
        fn = g.get(name)
        if callable(fn):
            return fn(db)
    return result


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: ida_mcp_shim.py <db-path> <code-file>", file=sys.stderr)
        return 2
    path, code_path = sys.argv[1], sys.argv[2]
    code = open(code_path, encoding="utf-8").read()
    stdout_buf: list[str] = []
    stderr_buf: list[str] = []

    class _Cap:
        def __init__(self, sink: list[str]) -> None:
            self._sink = sink

        def write(self, data: str) -> int:
            self._sink.append(data)
            return len(data)

        def flush(self) -> None:
            return None

    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _Cap(stdout_buf), _Cap(stderr_buf)
    payload: dict[str, Any]
    try:
        result = _exec_user(code, Database(path))
        payload = {
            "result": _jsonable(result),
            "stdout": "".join(stdout_buf),
            "stderr": "".join(stderr_buf),
        }
        rc = 0
    except Exception as exc:  # noqa: BLE001 - surface to MCP
        payload = {
            "result": None,
            "stdout": "".join(stdout_buf),
            "stderr": "".join(stderr_buf) + traceback.format_exc(),
            "error": str(exc),
        }
        rc = 1
    finally:
        sys.stdout, sys.stderr = real_out, real_err
    real_out.write(json.dumps(payload, ensure_ascii=False))
    real_out.write("\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
