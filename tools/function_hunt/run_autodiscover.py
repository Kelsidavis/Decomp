#!/usr/bin/env python3
# tools/function_hunt/run_autodiscover.py
from __future__ import annotations
import os, sys, json, time, re, pathlib
from typing import List, Dict, Any, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional enrich/report; tolerate absence
try:
    from enrich import enrich         # noqa
except Exception:
    def enrich(funcs, enable_capa=False, enable_yara=False, bin_path=None):  # type: ignore
        return funcs
try:
    from report import write_report   # noqa
except Exception:
    def write_report(labeled, out_dir="work/hunt"):  # type: ignore
        p = pathlib.Path(out_dir) / "report.md"
        p.write_text(f"Labeled functions: {len(labeled)}\n", encoding="utf-8")
        return str(p)

from label import llm_label_one

WORK      = pathlib.Path(os.getenv("WORK_DIR", "work"))
HUNT_DIR  = WORK / "hunt"
HUNT_DIR.mkdir(parents=True, exist_ok=True)
MAPPING   = HUNT_DIR / "functions.labeled.jsonl"
PROGRESS  = HUNT_DIR / ".progress"

LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "")
LLM_MODEL    = os.getenv("LLM_MODEL", "")
CONCURRENCY  = max(1, int(os.getenv("HUNT_LLM_CONCURRENCY", "6")))

HUNT_TOPN    = int(os.getenv("HUNT_TOPN", "1000")) if os.getenv("HUNT_TOPN","").isdigit() else None
HUNT_LIMIT   = int(os.getenv("HUNT_LIMIT","0")) or None
HUNT_MIN_SIZE= int(os.getenv("HUNT_MIN_SIZE","0"))

BIN_EXTS = (".exe", ".dll", ".bin", ".elf", ".so", ".dylib", "")
JSON_PATTERNS = (
    "_out.json", "-out.json", ".out.json", ".target_out.json", "target_out.json",
    "target_out.ndjson", "analysis.json"
)

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())

def _best_binary(work_dir: pathlib.Path) -> Optional[pathlib.Path]:
    # Pick the newest file at the ROOT of work/ with common binary exts; avoid recovered assets/cmake by not recursing
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
    # Try exact root-level candidates
    for suffix in JSON_PATTERNS:
        if stem:
            pat = f"{bin_path.stem}{suffix}"
            p = work_dir / pat
            if p.exists() and p.is_file(): exacts.append(p)
        p2 = work_dir / suffix
        if p2.exists() and p2.is_file(): exacts.append(p2)
    if exacts:
        exacts.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return exacts[0]
    # Fallback: any *out*.json at root
    loose = [p for p in work_dir.glob("*") if p.is_file() and p.suffix.lower()==".json" and "out" in p.name.lower()]
    if not loose: return None

    def score(p: pathlib.Path):
        s = 0
        base_norm = _norm(re.sub(r"(?:[_\-.]?target)?[_\-.]?out$", "", p.stem))
        if stem and base_norm == stem: s += 10
        elif stem and (stem in base_norm or base_norm in stem): s += 6
        s += int(p.stat().st_mtime / 60)  # prefer newer
        return s

    loose.sort(key=score, reverse=True)
    return loose[0] if loose else None

def _load_existing_keys(path: pathlib.Path) -> Set[str]:
    keys: Set[str] = set()
    if not path.exists(): return keys
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            try:
                obj = json.loads(ln)
            except Exception:
                continue
            k = str(obj.get("_addr") or obj.get("_orig_name") or obj.get("name") or "")
            if k: keys.add(k)
    return keys

def _read_jsonl_or_json(path: pathlib.Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text: return None
    # Try JSON
    try: return json.loads(text)
    except Exception: pass
    # Try JSON Lines
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln: continue
        try: out.append(json.loads(ln))
        except Exception: pass
    return {"functions": out} if out else None

def load_functions(target_out: pathlib.Path) -> List[Dict[str, Any]]:
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
        norm.append({
            "address": addr,
            "name": str(name),
            "size": int(size) if isinstance(size, (int,float)) else 0,
            "snippet": str(snippet)[:4000],
            "imports": imports[:100] if isinstance(imports, list) else [],
            "strings": strings[:100] if isinstance(strings, list) else [],
            "signals": {}
        })
    return norm

def main() -> int:
    bin_path = _best_binary(WORK)
    tout     = _best_target_out(WORK, bin_path)

    print(f"[hunt] binary     : {bin_path or (WORK/'YourProgram.exe')}")
    print(f"[hunt] target_out : {tout or (WORK/'target_out.json')}")
    print(f"[hunt] out dir    : {HUNT_DIR}")

    funcs = load_functions(tout) if tout else []
    print(f"[hunt] discovered : {len(funcs)}")

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

    # Enrich (optional)
    enable_capa = bool(os.getenv("HUNT_CAPA"))
    enable_yara = bool(os.getenv("HUNT_YARA"))
    enrich(funcs, enable_capa=enable_capa, enable_yara=enable_yara, bin_path=str(bin_path) if bin_path else None)
    print("[hunt] starting llm_label_batch()…")

    # Resume: skip already-labeled
    done_keys = _load_existing_keys(MAPPING)
    if done_keys:
        before = len(funcs)
        funcs = [f for f in funcs if str(f.get("address") or f.get("name")) not in done_keys]
        print(f"[hunt] resume: skipping already labeled → {before - len(funcs)} skipped")

    total = len(funcs)
    if total == 0:
        print("[hunt] nothing to label; writing minimal report…")
        if not MAPPING.exists(): MAPPING.touch()
        write_report([], out_dir=str(HUNT_DIR))
        return 0

    # Stream results to JSONL + track .progress
    HUNT_DIR.mkdir(parents=True, exist_ok=True)
    processed = 0
    every = max(5, total // 20)

    def work(item: Tuple[int, Dict[str, Any]]):
        i, f = item
        rec = llm_label_one(f, LLM_ENDPOINT, LLM_MODEL)
        return i, rec

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
    rp = write_report([], out_dir=str(HUNT_DIR))
    print(f"[hunt] wrote {rp}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

