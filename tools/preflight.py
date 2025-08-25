#!/usr/bin/env python3
"""
preflight.py — quick health check before running the pipeline.

Default behavior:
  - Verify pycparser importable
  - Verify fake_libc_include folder is discoverable
  - Try a tiny AST parse (no includes)
  - If system 'cpp' and fake includes are present, try a parse_file with -I <fake>

Optional:
  --full   : also check LLM endpoint, capa, yara, floss, gawk
  --strict : exit non-zero on failures (default: print warnings and exit 0)

Use:
  python3 tools/preflight.py
  python3 tools/preflight.py --full
  python3 tools/preflight.py --full --strict
"""
from __future__ import annotations
import os, sys, shutil, tempfile, textwrap, json, argparse, time
from pathlib import Path

GREEN = "\033[32m"
RED   = "\033[31m"
YEL   = "\033[33m"
DIM   = "\033[2m"
RST   = "\033[0m}"
RST   = "\033[0m"

def ok(msg: str) -> None:
    print(f"{GREEN}✅{RST} {msg}")

def warn(msg: str) -> None:
    print(f"{YEL}⚠️ {msg}{RST}")

def bad(msg: str) -> None:
    print(f"{RED}❌ {msg}{RST}")

def find_fake_libc_include() -> str | None:
    try:
        import pycparser, os as _os
        base = _os.path.dirname(pycparser.__file__)
        cand = _os.path.join(base, "utils", "fake_libc_include")
        if os.path.isdir(cand) and os.listdir(cand):
            return cand
    except Exception:
        return None
    return None

def check_pycparser(strict: bool) -> bool:
    # import
    try:
        import pycparser  # noqa
        ok("pycparser import: ok")
    except Exception as e:
        bad(f"pycparser import failed: {e}")
        return not strict  # pass in non-strict mode

    # fake includes
    fake = find_fake_libc_include()
    if fake:
        ok(f"fake_libc_include: {fake}")
    else:
        warn("fake_libc_include not found; AST mode may still work for simple files (HUMANIZE_AST will fallback).")

    # simple in-memory parse
    try:
        from pycparser import c_parser
        c_parser.CParser().parse("int add(int a,int b){return a+b;}")
        ok("AST parse (in-memory): ok")
    except Exception as e:
        bad(f"AST parse (in-memory) failed: {e}")
        if strict: return False

    # parse_file with cpp (only if both cpp and fake includes exist)
    cpp = shutil.which("cpp")
    if cpp and fake:
        code = "#include <stdint.h>\nint main(void){ return 0; }\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".c", delete=False) as tf:
            tf.write(code)
            tf.flush()
            path = tf.name
        try:
            from pycparser import parse_file
            parse_file(path, use_cpp=True, cpp_path=cpp, cpp_args=[f"-I{fake}"])
            ok("AST parse_file with cpp + fake includes: ok")
        except Exception as e:
            warn(f"AST parse_file failed (will fallback to regex on those files): {e}")
        finally:
            try: os.unlink(path)
            except Exception: pass
    else:
        if not cpp:
            warn("system 'cpp' not found; parse_file tests skipped (regex fallback will still work).")
        if not fake:
            warn("fake_libc_include not available; parse_file tests skipped (regex fallback will still work).")
    return True

def check_tool(name: str, pretty: str | None = None) -> bool:
    p = shutil.which(name)
    if p:
        ok(f"{pretty or name}: {p}")
        return True
    warn(f"{pretty or name} not found on PATH")
    return False

def check_llm(strict: bool) -> bool:
    endpoint = os.getenv("LLM_ENDPOINT", "")
    model    = os.getenv("LLM_MODEL", "")
    if not endpoint or not model:
        warn("LLM endpoint/model not set (LLM_ENDPOINT, LLM_MODEL) — reimplement/label will stub or fallback.")
        return not strict
    try:
        import requests  # noqa
    except Exception:
        warn("python 'requests' not available; skipping live LLM ping")
        return not strict

    try:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            "temperature": 0.0,
        }
        r = requests.post(endpoint, json=payload, timeout=5)
        r.raise_for_status()
        data = r.json()
        # very lenient sanity
        if "choices" in data:
            ok(f"LLM ping: ok ({model})")
            return True
        warn("LLM ping responded but payload looked unexpected")
        return not strict
    except Exception as e:
        warn(f"LLM ping failed ({endpoint}): {e}")
        return not strict

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="check LLM + tools (capa/yara/floss/gawk)")
    ap.add_argument("--strict", action="store_true", help="exit non-zero on failures")
    args = ap.parse_args()

    all_ok = True
    if not check_pycparser(args.strict):
        all_ok = False

    if args.full:
        # LLM
        if not check_llm(args.strict):
            all_ok = False
        # Tools
        t_ok = True
        t_ok &= check_tool("capa", "capa")
        t_ok &= check_tool("yara", "yara")
        t_ok &= check_tool("floss", "FLOSS")
        t_ok &= check_tool("gawk", "gawk")
        # keep non-strict by default
        if not t_ok and args.strict:
            all_ok = False

    if all_ok:
        ok("Preflight: all essential checks passed")
        return 0
    else:
        warn("Preflight: issues detected (continuing in non-strict mode)")
        return 1 if args.strict else 0

if __name__ == "__main__":
    raise SystemExit(main())

