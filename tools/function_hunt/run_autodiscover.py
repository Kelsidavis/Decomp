#!/usr/bin/env python3
# tools/function_hunt/run_autodiscover.py — autodetect inputs, FLOSS/CAPA/YARA enrich, resume-safe label, write mapping
from __future__ import annotations

import os
import re
import json
import shlex
import time
import bisect
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# local imports
from label import llm_label_one, llm_label_batch

# -------------------- paths & env --------------------
WORK      = Path(os.getenv("WORK_DIR", "work"))
HUNT_DIR  = WORK / "hunt"
HUNT_DIR.mkdir(parents=True, exist_ok=True)
MAPPING   = HUNT_DIR / "functions.labeled.jsonl"
PROGRESS  = Path(os.getenv("HUNT_PROGRESS_PATH", str(HUNT_DIR / "label.progress")))

LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "")
LLM_MODEL    = os.getenv("LLM_MODEL", "")

HUNT_TOPN     = int(os.getenv("HUNT_TOPN", "1000")) if os.getenv("HUNT_TOPN","").isdigit() else None
HUNT_LIMIT    = int(os.getenv("HUNT_LIMIT","0")) or None
HUNT_MIN_SIZE = int(os.getenv("HUNT_MIN_SIZE","0"))
HUNT_RESUME   = os.getenv("HUNT_RESUME","1").lower() in ("1","true","yes","on")

# FLOSS controls
ENABLE_FLOSS   = os.getenv("ENABLE_FLOSS", "1").lower() in ("1","true","yes","on")
FLOSS_OUT      = Path(os.getenv("FLOSS_OUT", str(HUNT_DIR / "floss.json")))
FLOSS_MINLEN   = os.getenv("FLOSS_MINLEN", "")
FLOSS_ONLY     = os.getenv("FLOSS_ONLY", "")            # e.g. "decoded stack tight"
FLOSS_ARGS_RAW = os.getenv("FLOSS_ARGS", "")            # extra raw args
FLOSS_PER_FN   = max(1, int(os.getenv("FLOSS_PER_FN", "20")))
FLOSS_FORCE    = os.getenv("FLOSS_FORCE", "0").lower() in ("1","true","yes","on")

# CAPA controls
ENABLE_CAPA    = os.getenv("ENABLE_CAPA","1").lower() in ("1","true","yes","on")
CAPA_OUT       = Path(os.getenv("CAPA_OUT", str(HUNT_DIR / "capa.json")))
CAPA_ARGS      = os.getenv("CAPA_ARGS", "-j -v")
CAPA_PER_FN    = max(1, int(os.getenv("CAPA_PER_FN","12")))

# YARA controls
ENABLE_YARA    = os.getenv("ENABLE_YARA","1").lower() in ("1","true","yes","on")
YARA_RULES_DIR = Path(os.getenv("YARA_RULES", "rules/yara"))
YARA_PER_FN    = max(1, int(os.getenv("YARA_PER_FN","8")))

MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "6000"))
MAX_PROMPT_LINES = int(os.getenv("MAX_PROMPT_LINES", "80"))
MIN_PROMPT_LINES = int(os.getenv("MIN_PROMPT_LINES", "50"))

BIN_EXTS = (".exe", ".dll", ".bin", ".elf", ".so", ".dylib", "")

JSON_PATTERNS = (
    "_out.json", "-out.json", ".out.json", ".target_out.json", "target_out.json",
    "target_out.ndjson", "analysis.json"
)

# -------------------- basic helpers --------------------
def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

def _parse_hex(addr: Any) -> Optional[int]:
    if addr is None: return None
    if isinstance(addr, int): return addr
    s = str(addr).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 16)
    except Exception:
        try: return int(s)
        except Exception: return None

def _window_lines(s: str, min_lines: int, max_lines: int, max_chars: int) -> str:
    if not s: return s
    lines = s.splitlines()
    n = min(max(len(lines), min_lines), max_lines)
    w = "\n".join(lines[:n])
    if len(w) > max_chars:
        w = w[:max_chars]
    return w

def _group_iat(imports: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for imp in imports or []:
        dll, sym = None, None
        if "!" in imp: dll, sym = imp.split("!", 1)
        elif "." in imp: dll, sym = imp.split(".", 1)
        else: dll, sym = "unknown", imp
        dll = dll.replace(".dll", "").upper()
        out.setdefault(dll, [])
        if sym not in out[dll]:
            out[dll].append(sym)
    return out

def _best_binary(work_dir: Path) -> Optional[Path]:
    cands: List[Path] = []
    for p in work_dir.iterdir():
        if not p.is_file(): continue
        if p.suffix.lower() in BIN_EXTS:
            cands.append(p)
    if not cands: return None
    cands.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0]

def _best_target_out(work_dir: Path, bin_path: Optional[Path]) -> Optional[Path]:
    stem = _norm(bin_path.stem) if bin_path else ""
    exacts: List[Path] = []
    for suffix in JSON_PATTERNS:
        if bin_path:
            p = work_dir / f"{bin_path.stem}{suffix}"
            if p.exists() and p.is_file(): exacts.append(p)
        p2 = work_dir / suffix
        if p2.exists() and p2.is_file(): exacts.append(p2)
    if exacts:
        exacts.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return exacts[0]
    loose = [p for p in work_dir.glob("*") if p.is_file() and p.suffix.lower()==".json" and "out" in p.name.lower()]
    if not loose: return None

    def score(p: Path):
        s = 0
        base_norm = _norm(re.sub(r"(?:[_\-.]?target)?[_\-.]?out$", "", p.stem))
        if stem and base_norm == stem: s += 10
        elif stem and (stem in base_norm or base_norm in stem): s += 6
        s += int(p.stat().st_mtime / 60)
        return s

    loose.sort(key=score, reverse=True)
    return loose[0] if loose else None

def _read_jsonl_or_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text: return None
    try: return json.loads(text)
    except Exception: pass
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln: continue
        try: out.append(json.loads(ln))
        except Exception: pass
    return {"functions": out} if out else None

def _string_xrefs(func: Dict[str,Any]) -> List[str]:
    s = func.get("string_xrefs")
    if isinstance(s, list) and s:
        return list(dict.fromkeys([str(x) for x in s]))[:32]
    return list(dict.fromkeys([str(x) for x in (func.get("strings") or [])]))[:32]

# -------------------- FLOSS --------------------
def _run_floss(bin_path: Path) -> None:
    if not ENABLE_FLOSS: return
    if FLOSS_OUT.exists() and not FLOSS_FORCE:
        return
    args = ["floss", "-j", "-v"]
    if FLOSS_MINLEN:
        args += ["-n", str(FLOSS_MINLEN)]
    if FLOSS_ONLY:
        args += ["--only"] + FLOSS_ONLY.split() + ["--"]
    extra = shlex.split(FLOSS_ARGS_RAW) if FLOSS_ARGS_RAW else []
    args += extra
    args += [str(bin_path)]
    print(f"[floss] running: {' '.join(args)}")
    try:
        res = subprocess.run(args, check=True, capture_output=True, text=True)
        FLOSS_OUT.write_text(res.stdout, encoding="utf-8")
        print(f"[floss] wrote {FLOSS_OUT}")
    except FileNotFoundError:
        print("[floss] not installed (flare-floss). Skipping decoded strings.")
    except subprocess.CalledProcessError as e:
        print(f"[floss] error (exit {e.returncode}). stderr:\n{(e.stderr or '')[:2000]}")
    except Exception as e:
        print(f"[floss] error: {e}")

def _load_floss_pairs(path: Path) -> List[Tuple[int,str]]:
    pairs: List[Tuple[int,str]] = []
    if not path.exists(): return pairs
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return pairs
    buckets = []
    for k in ("strings","decoded_strings", "stack_strings", "tight_strings"):
        v = data.get(k)
        if isinstance(v, list): buckets.append(v)
    for bucket in buckets:
        for s in bucket:
            if not isinstance(s, dict): continue
            text = s.get("string") or s.get("decoded") or s.get("value") or ""
            va   = s.get("va") or s.get("address") or (s.get("function") or {}).get("va")
            if not text or va is None: continue
            try:
                va_int = int(va) if isinstance(va, int) else int(str(va), 16) if str(va).lower().startswith("0x") else int(str(va), 16)
            except Exception:
                continue
            pairs.append((va_int, str(text)))
    return pairs

# -------------------- CAPA --------------------
def _run_capa(bin_path: Path) -> None:
    if not ENABLE_CAPA: return
    if CAPA_OUT.exists() and CAPA_OUT.stat().st_size > 0:
        return
    args = ["capa"] + shlex.split(CAPA_ARGS) + [str(bin_path)]
    print(f"[capa] running: {' '.join(args)}")
    try:
        res = subprocess.run(args, check=True, capture_output=True, text=True)
        CAPA_OUT.write_text(res.stdout, encoding="utf-8")
        print(f"[capa] wrote {CAPA_OUT}")
    except FileNotFoundError:
        print("[capa] tool not found. Install `capa` (FireEye/flare-capa) to enable CAPA evidence.")
    except subprocess.CalledProcessError as e:
        print(f"[capa] error (exit {e.returncode}). stderr:\n{(e.stderr or '')[:2000]}")
    except Exception as e:
        print(f"[capa] error: {e}")

def _load_capa_pairs(path: Path) -> List[Tuple[int,str]]:
    """Return list of (va, rule_name)."""
    pairs: List[Tuple[int,str]] = []
    if not path.exists(): return pairs
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return pairs
    # Capa JSON layouts can vary by version. Try common shapes:
    rules = data.get("rules") or []
    for r in rules:
        name = r.get("meta", {}).get("name") or r.get("name")
        if not name: continue
        matches = r.get("matches") or []
        for m in matches:
            # hunt for a VA-ish field
            va = m.get("va") or m.get("address")
            if va is None:
                # sometimes nested
                locs = m.get("locations") or []
                for loc in locs:
                    va = loc.get("va") or loc.get("address")
                    if va is not None:
                        break
            if va is None:  # last resort: skip
                continue
            try:
                va_int = int(va) if isinstance(va, int) else int(str(va), 16) if str(va).lower().startswith("0x") else int(str(va), 16)
            except Exception:
                continue
            pairs.append((va_int, str(name)))
    return pairs

# -------------------- YARA --------------------
def _yara_compile_dir(dirpath: Path):
    try:
        import yara
    except Exception:
        print("[yara] python module not available; skipping YARA evidence.")
        return None
    if not dirpath.exists() or not any(dirpath.glob("**/*.yar*")):
        print(f"[yara] rules dir missing or empty: {dirpath} (skip)")
        return None
    try:
        # compile all rules in directory
        filepaths = [str(p) for p in dirpath.rglob("*.yar*")]
        namespaces = {f"ns{i}": fp for i, fp in enumerate(filepaths)}
        return yara.compile(filepaths=namespaces)
    except Exception as e:
        print(f"[yara] failed to compile rules: {e}")
        return None

def _run_yara(bin_path: Path) -> List[Tuple[int,str]]:
    """Return list of (file_offset, rule_name)"""
    if not ENABLE_YARA:
        return []
    rules = _yara_compile_dir(YARA_RULES_DIR)
    if not rules:
        return []
    try:
        import yara
        m = rules.match(str(bin_path), timeout=60)  # type: ignore
        pairs: List[Tuple[int,str]] = []
        for match in m:
            rname = match.rule
            # collect first few string instances (offsets are file offsets)
            seen = 0
            for s in match.strings:
                # s: (offset, identifier, data)
                try:
                    off = int(s[0])
                    pairs.append((off, rname))
                    seen += 1
                    if seen >= 8:
                        break
                except Exception:
                    continue
        print(f"[yara] matches: {len(m)} rules")
        return pairs
    except Exception as e:
        print(f"[yara] scan failed: {e}")
        return []

# -------------------- attach helpers --------------------
def _attach_pairs_by_va(funcs: List[Dict[str,Any]], pairs: List[Tuple[int,str]], key: str, per_fn: int) -> None:
    if not pairs: return
    ranges = []
    for f in funcs:
        start = _parse_hex(f.get("address") or f.get("addr"))
        size  = f.get("size") or 0
        end   = (start or 0) + (size or 0)
        if start is None: continue
        ranges.append((start, end, f))
    ranges.sort(key=lambda x: x[0])
    starts = [r[0] for r in ranges]
    for va, name in pairs:
        i = bisect.bisect_right(starts, va) - 1
        if 0 <= i < len(ranges):
            start, end, f = ranges[i]
            if start <= va < end:
                sig = f.setdefault("signals", {})
                lst = sig.setdefault(key, [])
                if isinstance(lst, list):
                    lst.append({"rule": name})
                    if len(lst) > per_fn:
                        del lst[0:len(lst)-per_fn]

def _attach_yara_by_file_offset(funcs: List[Dict[str,Any]], pairs: List[Tuple[int,str]], per_fn: int) -> None:
    """Map yara file offsets onto functions if functions expose file offset ranges."""
    if not pairs: return
    # Build ranges if we have offsets
    ranges = []
    for f in funcs:
        # Accept a variety of possible keys for file offsets if present in target_out
        start_off = f.get("file_off_start") or f.get("file_offset_start") or f.get("file_off") or f.get("file_offset")
        end_off   = f.get("file_off_end")   or f.get("file_offset_end")
        if start_off is None or end_off is None:
            continue
        try:
            s = int(start_off)
            e = int(end_off)
            if e <= s:
                continue
            ranges.append((s, e, f))
        except Exception:
            continue
    if not ranges:
        # No usable file offsets; attach YARA at module scope by sprinkling across biggest functions for visibility
        big = sorted(funcs, key=lambda x: int(x.get("size") or 0), reverse=True)[:min(50, len(funcs))]
        for _, rule in pairs[:len(big)]:
            for f in big:
                sig = f.setdefault("signals", {})
                lst = sig.setdefault("yara_hits", [])
                lst.append({"rule": rule})
                if len(lst) > per_fn:
                    del lst[0:len(lst)-per_fn]
        return
    ranges.sort(key=lambda x: x[0])
    starts = [r[0] for r in ranges]
    for off, rule in pairs:
        i = bisect.bisect_right(starts, off) - 1
        if 0 <= i < len(ranges):
            s, e, f = ranges[i]
            if s <= off < e:
                sig = f.setdefault("signals", {})
                lst = sig.setdefault("yara_hits", [])
                lst.append({"rule": rule})
                if len(lst) > per_fn:
                    del lst[0:len(lst)-per_fn]

# -------------------- load/normalize funcs --------------------
def load_functions(target_out: Path, module_name: str) -> List[Dict[str, Any]]:
    if not target_out or not target_out.exists():
        print(f"[hunt] WARNING: target_out missing: {target_out}")
        return []
    try:
        data = _read_jsonl_or_json(target_out)
    except Exception as e:
        print(f"[hunt] failed to read JSON: {target_out} ({e})")
        return []
    if data is None:
        return []
    funcs = data.get("functions") if isinstance(data, dict) else data
    if not isinstance(funcs, list):
        print("[hunt] no functions array in target_out")
        return []

    norm: List[Dict[str, Any]] = []
    for f in funcs:
        if not isinstance(f, dict): continue
        name    = f.get("name") or f.get("func_name") or f.get("symbol") or f.get("original_name") or "sub_unknown"
        addr    = f.get("address") or f.get("addr") or f.get("rva") or ""
        if isinstance(addr, int): addr = hex(addr)
        size    = f.get("size") or f.get("len") or 0
        snippet = f.get("decompiled") or f.get("pseudocode") or f.get("body") or f.get("snippet") or ""
        imports = f.get("imports") or f.get("calls") or []
        strings = f.get("strings") or []
        callers = f.get("callers") or []
        callees = f.get("callees") or f.get("children") or []
        xrefs   = _string_xrefs(f)

        snippet = _window_lines(str(snippet), MIN_PROMPT_LINES, MAX_PROMPT_LINES, MAX_PROMPT_CHARS)

        sig = {
            "module": module_name,
            "iat_by_dll": _group_iat(imports),
            "string_xrefs": xrefs,
            "callers": callers, "callees": callees,
        }
        # Preserve file offsets if provided; helps YARA mapping
        for k in ("file_off_start","file_off_end","file_offset_start","file_offset_end","file_off","file_offset"):
            if k in f:
                sig[k] = f[k]

        norm.append({
            "address": addr,
            "name": str(name),
            "size": int(size) if isinstance(size, (int,float)) else 0,
            "snippet": snippet,
            "imports": imports[:200] if isinstance(imports, list) else [],
            "strings": strings[:200] if isinstance(strings, list) else [],
            "signals": sig,
        })
    return norm

# -------------------- resume helpers --------------------
def _progress_read() -> int:
    """Return last processed index (0-based), or -1 if none."""
    if not PROGRESS.exists(): return -1
    try:
        return int(PROGRESS.read_text(encoding="utf-8").strip())
    except Exception:
        return -1

def _progress_write(i: int) -> None:
    try:
        PROGRESS.write_text(str(i), encoding="utf-8")
    except Exception:
        pass

def _progress_clear() -> None:
    try:
        if PROGRESS.exists():
            PROGRESS.unlink()
    except Exception:
        pass

# -------------------- main --------------------
def main() -> int:
    start_ts = time.time()
    bin_path = _best_binary(WORK)
    tout     = _best_target_out(WORK, bin_path)
    module   = bin_path.name if bin_path else "unknown.bin"

    print(f"[hunt] binary     : {bin_path or (WORK/'YourProgram.exe')}")
    print(f"[hunt] target_out : {tout or (WORK/'target_out.json')}")
    print(f"[hunt] out dir    : {HUNT_DIR}")

    funcs = load_functions(tout, module) if tout else []
    total_all = len(funcs)
    print(f"[hunt] discovered : {total_all}")

    # FLOSS
    if bin_path and ENABLE_FLOSS:
        _run_floss(bin_path)
        pairs = _load_floss_pairs(FLOSS_OUT)
        _attach_pairs_by_va(funcs, pairs, key="floss_strings", per_fn=FLOSS_PER_FN)
        print(f"[hunt] FLOSS attached: {len(pairs)} strings (capped per-fn={FLOSS_PER_FN})")

    # CAPA
    if bin_path and ENABLE_CAPA:
        _run_capa(bin_path)
        c_pairs = _load_capa_pairs(CAPA_OUT)
        _attach_pairs_by_va(funcs, c_pairs, key="capa_hits", per_fn=CAPA_PER_FN)
        print(f"[hunt] CAPA attached: {len(c_pairs)} hits (capped per-fn={CAPA_PER_FN})")

    # YARA
    if bin_path and ENABLE_YARA:
        y_pairs = _run_yara(bin_path)
        _attach_yara_by_file_offset(funcs, y_pairs, per_fn=YARA_PER_FN)
        print(f"[hunt] YARA attached: {len(y_pairs)} offsets (capped per-fn={YARA_PER_FN})")

    # Filters
    if HUNT_MIN_SIZE:
        before = len(funcs)
        funcs = [f for f in funcs if (f.get("size",0) or 0) >= HUNT_MIN_SIZE]
        print(f"[hunt] filtered by HUNT_MIN_SIZE={HUNT_MIN_SIZE}: {before} → {len(funcs)}")
    if HUNT_TOPN:
        funcs = sorted(funcs, key=lambda f: f.get("size",0), reverse=True)[:HUNT_TOPN]
        print(f"[hunt] taking top {HUNT_TOPN} by size (HUNT_TOPN) → {len(funcs)}")
    if HUNT_LIMIT:
        funcs = funcs[:HUNT_LIMIT]
        print(f"[hunt] limiting to {HUNT_LIMIT} (HUNT_LIMIT)")
    total = len(funcs)
    print(f"[hunt] functions normalized: {total}")

    # --------------- Resume-aware labeling ---------------
    if total == 0:
        # Still produce empty mapping to avoid later stage errors
        MAPPING.write_text("", encoding="utf-8")
        print(f"[hunt] wrote {MAPPING} (empty)")
        return 0

    start_idx = -1
    if HUNT_RESUME:
        # If mapping exists and has lines, we’ll prefer .progress
        if PROGRESS.exists():
            start_idx = _progress_read()
        else:
            # infer from existing mapping line count (conservative)
            if MAPPING.exists():
                try:
                    existing_lines = sum(1 for _ in MAPPING.open("r", encoding="utf-8", errors="ignore"))
                    start_idx = existing_lines - 1
                except Exception:
                    start_idx = -1
        if start_idx >= total - 1:
            print("[hunt] resume: already complete; nothing to do.")
            return 0
        if start_idx >= 0:
            print(f"[hunt] resume enabled — continuing at index {start_idx+1}/{total-1}")

    # Open mapping in append mode when resuming, else truncate
    mode = "a" if (HUNT_RESUME and MAPPING.exists() and start_idx >= 0) else "w"
    done = max(0, start_idx + 1)
    last_log = time.time()

    with MAPPING.open(mode, encoding="utf-8") as out:
        for i, f in enumerate(funcs):
            if i <= start_idx:
                continue

            rec = llm_label_one(f, LLM_ENDPOINT, LLM_MODEL)
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            _progress_write(i)

            done += 1
            now = time.time()
            if (now - last_log) >= 1.5 or done == total:
                elapsed = now - start_ts
                rate = done/elapsed if elapsed>0 else 0.0
                remain = int((total-done)/rate) if rate>0 else -1
                eta = time.strftime("%H:%M:%S", time.gmtime(remain)) if remain>=0 else "??:??:??"
                pct = int(100*done/total)
                print(f"[hunt] progress {done}/{total} | {pct}% | elapsed {int(elapsed)}s | ETA {eta}")
                last_log = now

    _progress_clear()
    print(f"[hunt] wrote {MAPPING}")
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())

