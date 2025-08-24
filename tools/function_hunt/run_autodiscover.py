#!/usr/bin/env python3
# tools/function_hunt/run_autodiscover.py — robust one-pass pipeline
from __future__ import annotations
import json, os, re, sys, time, hashlib
from pathlib import Path
from typing import Any, Dict, List, Tuple

from enrich import enrich            # mutates in place; may return None
from label import llm_label_batch
from report import write_report      # writes report.md; we also ensure JSONL

# -------------------------
# Loose JSON tolerant read
# -------------------------
HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")

def load_loose_json(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    items, ok, lines = [], 0, text.splitlines()
    for ln in lines:
        s = ln.strip()
        if not s: continue
        try:
            items.append(json.loads(s)); ok += 1
        except Exception:
            pass
    if ok and ok >= max(1, len(lines)//2):
        return items
    try:
        fixed = "[" + re.sub(r"}\s*{", "},{", text) + "]"
        return json.loads(fixed)
    except Exception as e:
        raise ValueError(f"Unrecognized JSON format in {path}: {e}")

# -------------------------
# Schema coercion helpers
# -------------------------
NAME_KEYS = ["name","func_name","symbol","original_name","label","demangled","demangled_name","mangled"]
ADDR_KEYS = ["address","addr","rva","start","start_ea","ea","entry"]
SIZE_KEYS = ["size","len","length","nbytes","byte_len","end_ea_minus_start_ea"]
CODE_KEYS = ["decompiled","pseudocode","c","code","decomp","hlil","pcode","pseudo"]
IMPT_KEYS = ["imports","calls","callees","xrefs_to","external_calls"]
STR_KEYS  = ["strings","strs","literals","const_strings"]

def _parse_int_like(x: Any) -> int | None:
    if x is None or isinstance(x, bool): return None
    if isinstance(x, int): return x
    if isinstance(x, float): return int(x) or None
    if isinstance(x, str):
        s = x.strip()
        try:
            if s.startswith(("0x","0X")) and HEX_RE.match(s): return int(s, 16)
            if s.isdigit(): return int(s, 10)
            if HEX_RE.match(s): return int(s, 16)
        except Exception: return None
    return None

def _first_hit(d: Dict[str, Any], keys: List[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None

def _get_str_list(d: Dict[str, Any], keys: List[str]) -> List[str]:
    v = _first_hit(d, keys)
    if v is None: return []
    if isinstance(v, list):
        out = []
        for t in v:
            try:
                s = str(t)[:256]
                if "This program cannot be run in DOS mode" in s:  # filter noisy PE header
                    continue
                out.append(s)
            except Exception:
                pass
        return out[:200]
    s = str(v)[:256]
    return [] if "This program cannot be run in DOS mode" in s else [s]

def _get_text(d: Dict[str, Any], keys: List[str]) -> str:
    v = _first_hit(d, keys)
    if v is None: return ""
    if isinstance(v, (dict, list)):
        try: return json.dumps(v)[:4000]
        except Exception: return ""
    return str(v)[:4000]

def _coerce_one(f: Dict[str, Any]) -> Dict[str, Any] | None:
    name     = _first_hit(f, NAME_KEYS)
    addr_raw = _first_hit(f, ADDR_KEYS)
    addr_i   = _parse_int_like(addr_raw)
    addr_hex = ("0x%X" % addr_i) if addr_i is not None else (str(addr_raw) if addr_raw else "")
    size_raw = _first_hit(f, SIZE_KEYS)
    size_i   = _parse_int_like(size_raw) or 0
    snippet  = _get_text(f, CODE_KEYS)
    imports  = _get_str_list(f, IMPT_KEYS)
    strings  = _get_str_list(f, STR_KEYS)

    if not name:
        if addr_i is not None:
            name = f"sub_{addr_i:x}"
        else:
            name = "sub_unknown"

    if not addr_hex and not snippet and not imports and not strings:
        return None

    return {
        "address": addr_hex,
        "name": str(name),
        "size": int(size_i),
        "snippet": snippet,
        "imports": imports,
        "strings": strings,
        "signals": {}
    }

def _gather_funcs(obj: Any, out: List[Dict[str, Any]]):
    if isinstance(obj, dict):
        for key in ("functions","funcs","items","nodes","list"):
            if key in obj and isinstance(obj[key], list):
                for it in obj[key]:
                    _gather_funcs(it, out)
        coerced = _coerce_one(obj)
        if coerced: out.append(coerced)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _gather_funcs(v, out)
    elif isinstance(obj, list):
        for it in obj:
            _gather_funcs(it, out)

def _coerce_funcs_any(target: Any) -> List[Dict[str, Any]]:
    tmp: List[Dict[str, Any]] = []
    _gather_funcs(target, tmp)
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for f in tmp:
        key = (f["name"], f["address"])
        if key in seen: continue
        seen.add(key)
        uniq.append(f)
    return uniq

# -------------------------
# Effective size & dedupe
# -------------------------
def _build_next_addr_delta(funcs: List[Dict[str, Any]]) -> Dict[int,int | None]:
    addrs = sorted(a for a in (_parse_int_like(f.get("address")) for f in funcs) if a is not None)
    nxt: Dict[int,int | None] = {}
    for i, a in enumerate(addrs):
        nxt[a] = (addrs[i+1] - a) if (i+1 < len(addrs)) else None
    return nxt

def _eff_size(f: Dict[str, Any], nxt: Dict[int,int | None]) -> int:
    sz = f.get("size") or 0
    if sz: return int(sz)
    ai = _parse_int_like(f.get("address"))
    if ai is not None:
        d = nxt.get(ai)
        if d and d > 0:
            return min(d, 4096)
    snip = f.get("snippet") or ""
    return min(4096, max(0, len(snip)//4)) if snip else 0

def _norm_snippet(s: str) -> str:
    if not s: return ""
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s[:4000]

def _dedupe_by_snippet(funcs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[int]]:
    uniq: List[Dict[str, Any]] = []
    idx_map: List[int] = [0]*len(funcs)
    seen: Dict[str,int] = {}
    for i, f in enumerate(funcs):
        key = hashlib.sha1(_norm_snippet(f.get("snippet","")).encode("utf-8")).hexdigest() if f.get("snippet") else None
        if key is None:
            idx_map[i] = len(uniq)
            uniq.append(f)
            continue
        j = seen.get(key)
        if j is None:
            j = len(uniq)
            seen[key] = j
            uniq.append(f)
        idx_map[i] = j
    return uniq, idx_map

# -------------------------
# Work dir autodiscovery
# -------------------------
def _best_bin(work_dir: Path) -> Path | None:
    cands = [p for p in work_dir.iterdir()
             if p.is_file() and p.suffix.lower() not in {".json",".md",".txt",".log",".yml",".yaml",".toml"}]
    if not cands: return None
    def score(p: Path):
        s = 0
        if p.name.lower().startswith("target"): s += 3
        if p.suffix.lower() in (".exe",".dll"): s += 2
        s += int(p.stat().st_mtime)
        return s
    cands.sort(key=score, reverse=True)
    return cands[0]

def _best_target_out(work_dir: Path, bin_path: Path | None) -> Path | None:
    if not bin_path: return None
    stem = bin_path.stem
    exact = work_dir / f"{stem}_out.json"
    if exact.exists(): return exact
    cands = [p for p in work_dir.glob("*.json") if "out" in p.name.lower()]
    if not cands: return None
    def score(p: Path):
        s = 0
        n = p.name.lower()
        if stem.lower() in n: s += 5
        if "target_out" in n: s += 3
        s += int(p.stat().st_mtime)
        return s
    cands.sort(key=score, reverse=True)
    return cands[0]

# -------------------------
# Main
# -------------------------
def main():
    work = Path("work")
    work.mkdir(exist_ok=True)
    bin_path = _best_bin(work)
    target_out = _best_target_out(work, bin_path)

    if not bin_path or not target_out:
        print("[hunt] no binary or target_out found in work/", file=sys.stderr)
        sys.exit(2)

    out_dir = work / "hunt"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[hunt] binary     : {bin_path}")
    print(f"[hunt] target_out : {target_out}")
    print(f"[hunt] out dir    : {out_dir}")

    target = load_loose_json(target_out)
    funcs = _coerce_funcs_any(target)
    print(f"[hunt] discovered: {len(funcs)}", flush=True)

    # Effective size map
    nxt = _build_next_addr_delta(funcs)

    # Filters
    min_size = int(os.getenv("HUNT_MIN_SIZE","0") or "0")
    if min_size > 0:
        before = len(funcs)
        funcs = [f for f in funcs if _eff_size(f, nxt) >= min_size]
        print(f"[hunt] filtered by HUNT_MIN_SIZE={min_size}: {before} → {len(funcs)}", flush=True)

    topn = int(os.getenv("HUNT_TOPN","0") or "0")
    if topn > 0 and len(funcs) > topn:
        funcs.sort(key=lambda f: _eff_size(f, nxt), reverse=True)
        funcs = funcs[:topn]
        print(f"[hunt] taking top {topn} by size (HUNT_TOPN) → {len(funcs)}", flush=True)

    lim = int(os.getenv("HUNT_LIMIT","0") or "0")
    if lim > 0 and len(funcs) > lim:
        funcs = funcs[:lim]
        print(f"[hunt] limiting to first {len(funcs)} due to HUNT_LIMIT", flush=True)

    print(f"[hunt] functions normalized: {len(funcs)}", flush=True)

    # Optional dedupe
    do_dedupe = os.getenv("HUNT_DEDUPE", "1") not in ("0","false","False","no","No")
    if do_dedupe and funcs:
        uniq, idx_map = _dedupe_by_snippet(funcs)
        print(f"[hunt] dedupe by snippet: unique={len(uniq)} / total={len(funcs)}", flush=True)
        label_input = uniq
    else:
        idx_map = list(range(len(funcs)))
        label_input = funcs

    # Enrich (mutates in place; may return None)
    print("[hunt] starting enrich()…", flush=True)
    enable_capa = bool(os.getenv("HUNT_CAPA", "1"))
    enable_yara = bool(os.getenv("HUNT_YARA", "1"))
    ret = enrich(label_input, enable_capa, enable_yara, str(bin_path))
    if ret is not None:
        label_input = ret
    print("[hunt] enrich() done.", flush=True)

    # Label with LLM
    print("[hunt] starting llm_label_batch()…", flush=True)
    labeled_unique = llm_label_batch(label_input, os.getenv("LLM_ENDPOINT",""), os.getenv("LLM_MODEL",""))
    print("[hunt] llm_label_batch() done.", flush=True)

    # Expand labels back to full set if deduped
    if do_dedupe and funcs:
        labeled: List[Dict[str, Any]] = []
        for i, f in enumerate(funcs):
            lu = labeled_unique[idx_map[i]]
            li = dict(lu)
            li["_addr"] = f.get("address")
            li["_orig_name"] = f.get("name")
            labeled.append(li)
    else:
        labeled = []
        for i, f in enumerate(funcs):
            li = dict(labeled_unique[i])
            li["_addr"] = f.get("address")
            li["_orig_name"] = f.get("name")
            labeled.append(li)

    # Write artifacts
    print("[hunt] writing report…", flush=True)
    write_report(labeled, out_dir=str(out_dir))
    jsonl_path = out_dir / "functions.labeled.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as f:
        for rec in labeled:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"[hunt] wrote {out_dir/'report.md'}  (functions: {len(labeled)})")
    return 0

if __name__ == "__main__":
    sys.exit(main())

