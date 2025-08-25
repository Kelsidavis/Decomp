#!/usr/bin/env python3
"""
preflight.py — quick health check before running the pipeline.

- Verifies pycparser and fake_libc_include (uses --fake-dir or FAKE_LIBC_DIR if set).
- Optional: LLM endpoint, capa/yara/floss/gawk via --full.
- --strict exits non-zero on any failure; messaging reflects strict mode.
"""
from __future__ import annotations
import os, sys, shutil, tempfile, argparse
from pathlib import Path

GREEN = "\033[32m"; RED = "\033[31m"; YEL = "\033[33m"; RST = "\033[0m"
def ok(m):   print(f"{GREEN}✅{RST} {m}")
def warn(m): print(f"{YEL}⚠️ {m}{RST}")
def bad(m):  print(f"{RED}❌ {m}{RST}")

def find_fake_libc_include(cli_path: str | None) -> Path | None:
    # 1) CLI override
    if cli_path:
        p = Path(cli_path)
        return p if p.is_dir() else None
    # 2) env
    env = os.getenv("FAKE_LIBC_DIR")
    if env and os.path.isdir(env):
        return Path(env)
    # 3) best-effort in-module
    try:
        import pycparser, os as _os
        cand = Path(_os.path.dirname(pycparser.__file__)) / "utils" / "fake_libc_include"
        if cand.is_dir() and any(cand.iterdir()):
            return cand
    except Exception:
        pass
    return None

def check_pycparser(strict: bool, fake_cli: str | None) -> bool:
    try:
        import pycparser  # noqa
        ok("pycparser import: ok")
    except Exception as e:
        bad(f"pycparser import failed: {e}")
        return False if strict else True

    fake = find_fake_libc_include(fake_cli)
    if fake:
        ok(f"fake_libc_include: {fake}")
    else:
        warn("fake_libc_include not found; set FAKE_LIBC_DIR or pass --fake-dir to enable richer AST parsing.")

    # in-memory parse
    try:
        from pycparser import c_parser
        c_parser.CParser().parse("int add(int a,int b){return a+b;}")
        ok("AST parse (in-memory): ok")
    except Exception as e:
        if strict:
            bad(f"AST parse (in-memory) failed: {e}")
            return False
        warn(f"AST parse (in-memory) failed: {e}")
        return True

    # parse_file only if we have cpp + fake headers
    cpp = shutil.which("cpp")
    if cpp and fake:
        code = "#include <stdint.h>\nint main(void){return 0;}\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".c", delete=False) as tf:
            tf.write(code); tf.flush(); path = tf.name
        try:
            from pycparser import parse_file
            parse_file(path, use_cpp=True, cpp_path=cpp, cpp_args=[f"-I{fake}"])
            ok("AST parse_file with cpp + fake includes: ok")
        except Exception as e:
            if strict:
                bad(f"AST parse_file failed: {e}")
                return False
            warn(f"AST parse_file failed (regex fallback will still work): {e}")
        finally:
            try: os.unlink(path)
            except Exception: pass
    else:
        if not cpp:  warn("system 'cpp' not found; parse_file test skipped.")
        if not fake: warn("fake_libc_include not available; parse_file test skipped.")
    return True

def check_tool(name: str, pretty: str | None = None) -> bool:
    p = shutil.which(name)
    if p: ok(f"{pretty or name}: {p}"); return True
    warn(f"{pretty or name} not found on PATH"); return False

def check_llm(strict: bool) -> bool:
    endpoint = os.getenv("LLM_ENDPOINT", "")
    model    = os.getenv("LLM_MODEL", "")
    if not endpoint or not model:
        if strict:
            bad("LLM endpoint/model not set (LLM_ENDPOINT, LLM_MODEL)")
            return False
        warn("LLM endpoint/model not set (LLM_ENDPOINT, LLM_MODEL) — label/reimpl will stub or fallback.")
        return True
    try:
        import requests
    except Exception:
        return True  # not fatal; humanize/analyze still run
    try:
        r = requests.post(endpoint, json={
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1, "temperature": 0.0
        }, timeout=5)
        r.raise_for_status()
        if "choices" in r.json():
            ok(f"LLM ping: ok ({model})")
            return True
        warn("LLM ping responded but payload looked unexpected")
        return not strict
    except Exception as e:
        if strict:
            bad(f"LLM ping failed ({endpoint}): {e}")
            return False
        warn(f"LLM ping failed ({endpoint}): {e}")
        return True

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="check LLM + tools (capa/yara/floss/gawk)")
    ap.add_argument("--strict", action="store_true", help="exit non-zero on failures")
    ap.add_argument("--fake-dir", help="path to fake_libc_include (overrides env)")
    args = ap.parse_args()

    all_ok = True
    if not check_pycparser(args.strict, args.fake_dir):
        all_ok = False

    if args.full:
        if not check_llm(args.strict):
            all_ok = False
        t_ok = True
        t_ok &= check_tool("capa", "capa")
        t_ok &= check_tool("yara", "yara")
        t_ok &= check_tool("floss", "FLOSS")
        t_ok &= check_tool("gawk", "gawk")
        if not t_ok and args.strict:
            all_ok = False

    if all_ok:
        ok("Preflight: all essential checks passed")
        return 0
    else:
        if args.strict:
            bad("Preflight: issues detected (strict mode) — exiting with status 1")
            return 1
        warn("Preflight: issues detected (non-strict) — continuing")
        return 0

if __name__ == "__main__":
    raise SystemExit(main())

