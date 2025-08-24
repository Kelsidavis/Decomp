#!/usr/bin/env python3
import json, sys, os, re, time
from pathlib import Path
from typing import Any, Dict, List

from enrich import enrich
from label import llm_label_batch
from report import write_report

# ---------- tolerant JSON loader ----------
def load_loose_json(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    # 1) normal JSON
    try:
        return json.loads(text)
    except Exception:
        pass
    # 2) JSON Lines (NDJSON)
    items, ok, lines = [], 0, text.splitlines()
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        try:
            items.append(json.loads(s)); ok += 1
        except Exception:
            pass
    if ok and ok >= max(1, len(lines)//2):
        return items
    # 3) concatenated objects ...}{...
    try:
        fixed = "[" + re.sub(r"}\s*{", "},{", text) + "]"
        return json.loads(fixed)
    except Exception as e:
        raise ValueError(f"Unrecognized JSON format in {path}: {e}")

# ---------- helpers for schema variance ----------
NAME_KEYS   = ["name","func_name","symbol","original_name","label","demangled","demangled_name","mangled"]
ADDR_KEYS   = ["address","addr","rva","start","start_ea","ea","entry"]
SIZE_KEYS   = ["size","len","length","nbytes","byte_len","end_ea_minus_start_ea"]
CODE_KEYS   = ["decompiled","pseudocode","c","code","decomp","hlil","pcode","pseudo"]
IMPT_KEYS   = ["imports","calls","callees","xrefs_to","external_calls"]
STR_KEYS    = ["strings","strs","literals","const_strings"]

HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")

def _parse_int_like(x: Any) -> int | None:
    if x is None: return None
    if isinstance(x, bool): return None
    if isinstance(x, (int,)):
        return int(x)
    if isinstance(x, float):
        # don’t treat tiny floats as addresses
        val = int(x)
        return val if val != 0 else None
    if isinstance(x, str):
        s = x.strip()
        try:
            if s.startswith(("0x","0X")) and HEX_RE.match(s):
                return int(s, 16)
            if s.isdigit():
                return int(s, 10)
            # sometimes decimal-ish in strings
            if HEX_RE.match(s):
                return int(s, 16)
        except Exception:
            return None
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
                out.append(str(t)[:256])
            except Exception:
                pass
        return out[:200]
    try:
        return [str(v)[:256]]
    except Exception:
        return []

def _get_text(d: Dict[str, Any], keys: List[str]) -> str:
    v = _first_hit(d, keys)
    if v is None: return ""
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v)[:4000]
        except Exception:
            return ""
    return str(v)[:4000]

def _coerce_one(f: Dict[str, Any]) -> Dict[str, Any] | None:
    # name
    name = _first_hit(f, NAME_KEYS)
    # address
    addr_raw = _first_hit(f, ADDR_KEYS)
    addr_i = _parse_int_like(addr_raw)
    addr_hex = ("0x%X" % addr_i) if addr_i is not None else (str(addr_raw) if addr_raw else "")
    # size
    size_raw = _first_hit(f, SIZE_KEYS)
    size_i = _parse_int_like(size_raw) or 0

    # snippet / imports / strings
    snippet = _get_text(f, CODE_KEYS)
    imports = _get_str_list(f, IMPT_KEYS)
    strings = _get_str_list(f, STR_KEYS)

    # name fallback from address
    if not name:
        if addr_i is not None:
            name = "sub_%x" % addr_i
        elif isinstance(addr_raw, str) and addr_raw:
            # strip 0x if present
            nn = addr_raw.lower().replace("0x","")
            nn = re.sub(r"[^0-9a-f]", "", nn)[:8] or "unknown"
            name = f"sub_{nn}"
        else:
            name = "sub_unknown"

    # drop totally empty entries (no address AND no code AND no imports/strings)
    if not addr_hex and not snippet and not imports and not strings:
        return None

    return {
        "address": addr_hex,
        "name": str(name),
        "size": int(size_i) if isinstance(size_i, int) else 0,
        "snippet": snippet,
        "imports": imports,
        "strings": strings,
        "signals": {}
    }

def _gather_funcs(obj: Any, out: List[Dict[str, Any]]):
    """Recursively walk obj and collect function-like dicts."""
    if isinstance(obj, dict):
        # common containers: {"functions":[...]} or {"items":[...]} etc.
        for key in ("functions","funcs","items","nodes","list"):
            if key in obj and isinstance(obj[key], list):
                for it in obj[key]:
                    _gather_funcs(it, out)
        # Also try coercing this dict itself
        coerced = _coerce_one(obj)
        if coerced:
            out.append(coerced)
        # Recurse into nested dicts (lightly)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _gather_funcs(v, out)
    elif isinstance(obj, list):
        for it in obj:
            _gather_funcs(it, out)

def _coerce_funcs_any(target: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    _gather_funcs(target, out)
    # de-duplicate by (name,address) pair
    seen = set()
    uniq = []
    for f in out:
        key = (f["name"], f["address"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq

# ---------- autodiscovery (TOP-LEVEL ONLY) ----------
BIN_EXTS = (".exe", ".dll", ".bin", ".elf", ".so", ".dylib", "")
JSON_PATTERNS = (
    "_out.json", "-out.json", ".out.json", ".target_out.json", "target_out.json",
    "target_out.ndjson", "analysis.json"
)

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())

def _best_bin(work_dir: Path) -> Path | None:
    candidates = []
    for p in work_dir.glob("*"):
        if not p.is_file(): continue
        suf = p.suffix.lower()
        if suf in {".json",".md",".txt",".log",".yml",".yaml",".toml"}: continue
        if suf in BIN_EXTS or (suf == "" and p.stat().st_size > 0):
            candidates.append(p)
    if not candidates:
        return None
    def score(p: Path):
        s = 0
        if p.name.lower().startswith("target"): s += 3
        if p.suffix.lower() in (".exe",".dll"): s += 2
        s += int(p.stat().st_mtime) // 1000
        return s
    candidates.sort(key=score, reverse=True)
    return candidates[0]

def _best_target_out(work_dir: Path, bin_path: Path | None) -> Path | None:
    stem = _norm(bin_path.stem) if bin_path else ""
    exacts = []
    for suffix in JSON_PATTERNS:
        if stem:
            p = work_dir / f"{bin_path.stem}{suffix}"
            if p.exists() and p.is_file(): exacts.append(p)
        p = work_dir / suffix
        if p.exists() and p.is_file(): exacts.append(p)
    if exacts:
        exacts.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return exacts[0]
    loose = [p for p in work_dir.glob("*") if p.is_file() and p.suffix.lower()==".json" and "out" in p.name.lower()]
    if not loose:
        return None
    def score(p: Path):
        s = 0
        base_norm = _norm(re.sub(r"(?:[_\-.]?target)?[_\-.]?out$", "", p.stem))
        if stem and base_norm == stem: s += 10
        elif stem and (stem in base_norm or base_norm in stem): s += 6
        if "target_out" in p.name.lower(): s += 2
        s += int(p.stat().st_mtime) // 1000
        return s
    loose.sort(key=score, reverse=True)
    return loose[0]

def main():
    work_dir = Path("work").resolve()
    if not work_dir.exists():
        print("[hunt] no ./work directory found; create it or set HUNT_BIN/HUNT_JSON", file=sys.stderr)
        return 2

    bin_override  = os.getenv("HUNT_BIN")
    json_override = os.getenv("HUNT_JSON")
    out_override  = os.getenv("HUNT_OUT")

    bin_path = Path(bin_override).resolve() if bin_override else _best_bin(work_dir)
    if not bin_path or not bin_path.exists():
        print("[hunt] could not find a binary at work/ (root only). Set HUNT_BIN=path/to/app.exe", file=sys.stderr)
        return 2

    if json_override:
        target_out = Path(json_override).resolve()
        if not target_out.exists():
            print(f"[hunt] HUNT_JSON not found: {target_out}", file=sys.stderr)
            return 2
    else:
        target_out = _best_target_out(work_dir, bin_path)
        if not target_out or not target_out.exists():
            print(f"[hunt] no matching *target_out.json at work/ root for '{bin_path.name}'. "
                  f"Place the JSON next to the binary or set HUNT_JSON=path/to/file.json", file=sys.stderr)
            return 2

    out_dir = Path(out_override).resolve() if out_override else (work_dir / "hunt")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[hunt] binary     : {bin_path}")
    print(f"[hunt] target_out : {target_out}")
    print(f"[hunt] out dir    : {out_dir}")

    try:
        target = load_loose_json(target_out)
    except Exception as e:
        print(f"[hunt] failed to read JSON (loose parser): {target_out} ({e})", file=sys.stderr)
        return 2

    # extract & normalize
    funcs = _coerce_funcs_any(target)

    # Optional gatekeepers for huge programs
    min_size = os.getenv("HUNT_MIN_SIZE")
    if min_size and min_size.isdigit():
        ms = int(min_size)
        before = len(funcs)
        funcs = [f for f in funcs if f.get("size",0) >= ms]
        print(f"[hunt] filtered by HUNT_MIN_SIZE={ms}: {before} → {len(funcs)}")

    topn = os.getenv("HUNT_TOPN")
    if topn and topn.isdigit():
        tn = int(topn)
        funcs.sort(key=lambda f: f.get("size",0), reverse=True)
        funcs = funcs[:tn]
        print(f"[hunt] taking top {tn} by size (HUNT_TOPN) → {len(funcs)}")

    lim = os.getenv("HUNT_LIMIT")
    if lim and lim.isdigit():
        funcs = funcs[:int(lim)]
        print(f"[hunt] limiting to first {len(funcs)} functions due to HUNT_LIMIT")

    # Debug quality of extraction
    n_unknown = sum(1 for f in funcs if f["name"].startswith("sub_unknown"))
    n_noaddr  = sum(1 for f in funcs if not f["address"])
    print(f"[hunt] functions normalized: {len(funcs)} (unknown-name: {n_unknown}, no-addr: {n_noaddr})", flush=True)

    print("[hunt] starting enrich()…", flush=True)
    t0 = time.time()
    enrich(funcs, enable_capa=bool(os.getenv("HUNT_CAPA")),
                  enable_yara=bool(os.getenv("HUNT_YARA")),
                  bin_path=str(bin_path))
    print(f"[hunt] enrich() done in {time.time()-t0:.1f}s", flush=True)

    print("[hunt] starting llm_label_batch()…", flush=True)
    t0 = time.time()
    labeled = llm_label_batch(funcs, os.getenv("LLM_ENDPOINT",""), os.getenv("LLM_MODEL",""))
    print(f"[hunt] llm_label_batch() done in {time.time()-t0:.1f}s", flush=True)

    print("[hunt] writing report…", flush=True)
    report_path = write_report(labeled, out_dir=str(out_dir))
    print(f"[hunt] wrote {report_path}  (functions: {len(funcs)})")
    return 0

if __name__ == "__main__":
    sys.exit(main())

