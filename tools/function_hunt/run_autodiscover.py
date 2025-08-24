#!/usr/bin/env python3
# tools/function_hunt/run_autodiscover.py
from __future__ import annotations
import os, sys, json, time, re, pathlib, subprocess, shlex
from typing import List, Dict, Any, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

WORK      = pathlib.Path(os.getenv("WORK_DIR", "work"))
HUNT_DIR  = WORK / "hunt"
HUNT_DIR.mkdir(parents=True, exist_ok=True)
MAPPING   = HUNT_DIR / "functions.labeled.jsonl"
PROGRESS  = HUNT_DIR / ".progress"

LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "")
LLM_MODEL    = os.getenv("LLM_MODEL", "")
CONCURRENCY  = max(1, int(os.getenv("HUNT_LLM_CONCURRENCY", "6")))

HUNT_TOPN     = int(os.getenv("HUNT_TOPN", "1000")) if os.getenv("HUNT_TOPN","").isdigit() else None
HUNT_LIMIT    = int(os.getenv("HUNT_LIMIT","0")) or None
HUNT_MIN_SIZE = int(os.getenv("HUNT_MIN_SIZE","0"))

# FLOSS controls
ENABLE_FLOSS   = os.getenv("ENABLE_FLOSS", "1").lower() in ("1","true","yes","on")
FLOSS_OUT      = pathlib.Path(os.getenv("FLOSS_OUT", str(HUNT_DIR / "floss.json")))
FLOSS_MINLEN   = os.getenv("FLOSS_MINLEN", "")
FLOSS_ONLY     = os.getenv("FLOSS_ONLY", "")            # e.g. "decoded stack tight"
FLOSS_ARGS_RAW = os.getenv("FLOSS_ARGS", "")            # extra raw args (split via shlex)
FLOSS_PER_FN   = max(1, int(os.getenv("FLOSS_PER_FN", "20")))
FLOSS_FORCE    = os.getenv("FLOSS_FORCE", "0").lower() in ("1","true","yes","on")

MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "6000"))
MAX_PROMPT_LINES = int(os.getenv("MAX_PROMPT_LINES", "80"))
MIN_PROMPT_LINES = int(os.getenv("MIN_PROMPT_LINES", "50"))

BIN_EXTS = (".exe", ".dll", ".bin", ".elf", ".so", ".dylib", "")
JSON_PATTERNS = (
    "_out.json", "-out.json", ".out.json", ".target_out.json", "target_out.json",
    "target_out.ndjson", "analysis.json"
)

# Import labeler here to avoid cycles
from label import llm_label_one

# ------------------ helpers ------------------
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
        if "!" in imp:
            dll, sym = imp.split("!", 1)
        elif "." in imp:
            dll, sym = imp.split(".", 1)
        else:
            dll, sym = "unknown", imp
        dll = dll.replace(".dll", "").upper()
        out.setdefault(dll, [])
        if sym not in out[dll]:
            out[dll].append(sym)
    return out

def _load_jsonl(path: pathlib.Path) -> List[Dict[str,Any]]:
    if not path or not path.exists(): return []
    out = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln: continue
            try: out.append(json.loads(ln))
            except Exception: pass
    return out

def _load_hits() -> Tuple[List[Dict[str,Any]], List[Dict[str,Any]]]:
    candidates = [
        WORK / "capa.jsonl", WORK / "capa.ndjson", HUNT_DIR / "capa.jsonl", HUNT_DIR / "capa.ndjson",
    ]
    capah = []
    for c in candidates:
        capah.extend(_load_jsonl(c))

    ycand = [WORK / "yara.jsonl", HUNT_DIR / "yara.jsonl"]
    yarah = []
    for c in ycand:
        yarah.extend(_load_jsonl(c))
    return capah, yarah

def _hits_for_range(hits: List[Dict[str,Any]], start: int, size: int) -> List[Dict[str,Any]]:
    if start is None or size is None: return []
    end = start + max(0, size)
    out = []
    for h in hits or []:
        ha = _parse_hex(h.get("addr") or h.get("start") or h.get("offset"))
        he = _parse_hex(h.get("end"))
        if ha is None and he is None:
            continue
        if he is None: he = ha
        if ha is None: ha = he
        if ha is None or he is None: continue
        if (ha >= start and ha < end) or (he > start and he <= end) or (ha <= start and he >= end):
            out.append(h)
    return out

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())

def _best_binary(work_dir: pathlib.Path) -> Optional[pathlib.Path]:
    cands: List[pathlib.Path] = []
    for p in work_dir.iterdir():
        if not p.is_file(): continue
        if p.suffix.lower() in BIN_EXTS:
            cands.append(p)
    if not cands: return None
    cands.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0]

def _best_target_out(work_dir: pathlib.Path, bin_path: Optional[pathlib.Path]) -> Optional[pathlib.Path]:
    stem = _norm(bin_path.stem) if bin_path else ""
    exacts: List[pathlib.Path] = []
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

    def score(p: pathlib.Path):
        s = 0
        base_norm = _norm(re.sub(r"(?:[_\-.]?target)?[_\-.]?out$", "", p.stem))
        if stem and base_norm == stem: s += 10
        elif stem and (stem in base_norm or base_norm in stem): s += 6
        s += int(p.stat().st_mtime / 60)
        return s

    loose.sort(key=score, reverse=True)
    return loose[0] if loose else None

def _read_jsonl_or_json(path: pathlib.Path) -> Any:
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

# ------------------ FLOSS integration ------------------
def _run_floss(bin_path: pathlib.Path) -> None:
    if not ENABLE_FLOSS:
        return
    if FLOSS_OUT.exists() and not FLOSS_FORCE:
        # already present
        return
    args = ["floss", "-j", "-v"]
    if FLOSS_MINLEN:
        args += ["-n", str(FLOSS_MINLEN)]
    if FLOSS_ONLY:
        # e.g. "decoded stack tight" -> ["--only","decoded","stack","tight","--"]
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
        print(f"[floss] error (exit {e.returncode}). stderr:\n{e.stderr[:4000]}")
    except Exception as e:
        print(f"[floss] error: {e}")

def _load_floss_pairs(path: pathlib.Path) -> List[Tuple[int,str]]:
    """
    Return list of (va, string). Handle several FLOSS JSON shapes.
    """
    pairs: List[Tuple[int,str]] = []
    if not path.exists(): return pairs
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return pairs

    # FLOSS variants
    buckets = []
    for k in ("strings", "decoded_strings", "stack_strings", "tight_strings"):
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

def _attach_floss(funcs: List[Dict[str,Any]], floss_pairs: List[Tuple[int,str]], max_per_fn: int = 20) -> None:
    """
    Mutates funcs: for each function (start..end) attach strings into signals['floss_strings'].
    """
    if not floss_pairs: return
    # prepare function ranges
    ranges = []
    for f in funcs:
        start = _parse_hex(f.get("address"))
        size  = f.get("size") or 0
        end   = (start or 0) + (size or 0)
        f["_start"] = start
        f["_end"]   = end
        ranges.append((start, end, f))
    ranges = [r for r in ranges if r[0] is not None]
    ranges.sort(key=lambda x: x[0])

    # binary search by start address
    starts = [r[0] for r in ranges]

    import bisect
    for va, s in floss_pairs:
        i = bisect.bisect_right(starts, va) - 1
        if 0 <= i < len(ranges):
            start, end, f = ranges[i]
            if start is not None and start <= va < end:
                sig = f.setdefault("signals", {})
                lst = sig.setdefault("floss_strings", [])
                if s not in lst:
                    lst.append(s)
                    if len(lst) > max_per_fn:
                        del lst[0:len(lst)-max_per_fn]

# ------------------ load/normalize funcs ------------------
def load_functions(target_out: pathlib.Path, module_name: str) -> List[Dict[str, Any]]:
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

        norm.append({
            "address": addr,
            "name": str(name),
            "size": int(size) if isinstance(size, (int,float)) else 0,
            "snippet": snippet,
            "imports": imports[:200] if isinstance(imports, list) else [],
            "strings": strings[:200] if isinstance(strings, list) else [],
            "signals": sig
        })
    return norm

# ------------------ main ------------------
def main() -> int:
    bin_path = _best_binary(WORK)
    tout     = _best_target_out(WORK, bin_path)
    module   = bin_path.name if bin_path else "unknown.bin"

    print(f"[hunt] binary     : {bin_path or (WORK/'YourProgram.exe')}")
    print(f"[hunt] target_out : {tout or (WORK/'target_out.json')}")
    print(f"[hunt] out dir    : {HUNT_DIR}")

    funcs = load_functions(tout, module) if tout else []
    print(f"[hunt] discovered : {len(funcs)}")

    # FLOSS
    if bin_path and ENABLE_FLOSS:
        _run_floss(bin_path)
        pairs = _load_floss_pairs(FLOSS_OUT)
        _attach_floss(funcs, pairs, max_per_fn=FLOSS_PER_FN)

    # CAPA/YARA enrich
    capah, yarah = _load_hits()
    if capah or yarah:
        for f in funcs:
            start = _parse_hex(f.get("address"))
            size  = f.get("size") or 0
            if start is None: continue
            capa_hits = _hits_for_range(capah, start, size)
            yara_hits = _hits_for_range(yarah, start, size)
            f["signals"].setdefault("capa_hits", capa_hits)
            f["signals"].setdefault("yara_hits", yara_hits)

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
    print(f"[hunt] functions normalized: {len(funcs)}")
    print(f"[hunt] starting llm_label_batch()…")

    # Resume: skip already-labeled
    done = set()
    if MAPPING.exists():
        with MAPPING.open("r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                try:
                    o = json.loads(ln)
                except Exception:
                    continue
                k = str(o.get("_addr") or o.get("_orig_name") or o.get("name") or "")
                if k: done.add(k)
    if done:
        before = len(funcs)
        funcs = [f for f in funcs if str(f.get("address") or f.get("name")) not in done]
        print(f"[hunt] resume: skipping already labeled → {before - len(funcs)} skipped")

    total = len(funcs)
    if total == 0:
        if not MAPPING.exists(): MAPPING.touch()
        print("[hunt] nothing to label.")
        return 0

    processed = 0
    every = max(5, total // 20)

    def work(item: Tuple[int, Dict[str, Any]]):
        i, f = item
        rec = llm_label_one(f, LLM_ENDPOINT, LLM_MODEL)
        return i, rec

    from label import _coerce_label  # for type hints only
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex, MAPPING.open("a", encoding="utf-8") as out:
        futs = {ex.submit(work, (i, f)): i for i, f in enumerate(funcs)}
        for k, fut in enumerate(as_completed(futs), 1):
            _, rec = fut.result()
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            processed += 1
            PROGRESS.write_text(str(processed), encoding="utf-8")
            if (k % every == 0) or (k == total):
                print(f"[llm] progress {k}/{total}")
    print("[hunt] llm_label_batch() done")
    return 0

if __name__ == "__main__":
    sys.exit(main())

