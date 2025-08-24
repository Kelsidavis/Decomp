#!/usr/bin/env python3
import json, sys, os, re, time
from pathlib import Path

from enrich import enrich
from label import llm_label_batch
from report import write_report

# ---------- tolerant JSON loader ----------
def load_loose_json(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    try:
        return json.loads(text)  # normal JSON
    except Exception:
        pass
    # JSON Lines
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
    # Concatenated objects ...}{...
    try:
        fixed = "[" + re.sub(r"}\s*{", "},{", text) + "]"
        return json.loads(fixed)
    except Exception as e:
        raise ValueError(f"Unrecognized JSON format in {path}: {e}")

# ---------- function normalization ----------
def _coerce_funcs(target):
    funcs = []
    if isinstance(target, dict) and isinstance(target.get("functions"), list):
        src = target["functions"]
    elif isinstance(target, list):
        src = target
    else:
        src = []

    for f in src:
        if not isinstance(f, dict):
            continue
        name = (
            f.get("name") or f.get("func_name") or f.get("symbol")
            or f.get("original_name") or "sub_unknown"
        )
        addr = f.get("address") or f.get("addr") or f.get("rva") or ""
        if isinstance(addr, int):
            addr = hex(addr)
        size = f.get("size") or f.get("len") or 0
        snippet = f.get("decompiled") or f.get("pseudocode") or f.get("body") or ""
        imports = f.get("imports") or f.get("calls") or []
        strings = f.get("strings") or []
        funcs.append({
            "address": addr,
            "name": str(name),
            "size": int(size) if isinstance(size, (int, float)) else 0,
            "snippet": str(snippet)[:4000],
            "imports": imports[:100] if isinstance(imports, list) else [],
            "strings": strings[:100] if isinstance(strings, list) else [],
            "signals": {}
        })
    return funcs

# ---------- autodiscovery (TOP-LEVEL ONLY) ----------
BIN_EXTS = (".exe", ".dll", ".bin", ".elf", ".so", ".dylib", "")
JSON_PATTERNS = (
    "_out.json", "-out.json", ".out.json", ".target_out.json", "target_out.json",
    "target_out.ndjson", "analysis.json"
)

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())

def _best_bin(work_dir: Path) -> Path | None:
    """Pick a binary only from the root of work/ (no recursion)."""
    candidates = []
    for p in work_dir.glob("*"):
        if not p.is_file():
            continue
        suf = p.suffix.lower()
        if suf in {".json", ".md", ".txt", ".log", ".yml", ".yaml", ".toml"}:
            continue
        if suf in BIN_EXTS or (suf == "" and p.stat().st_size > 0):
            candidates.append(p)
    if not candidates:
        return None
    def score(p: Path):
        s = 0
        if p.name.lower().startswith("target"): s += 3
        if p.suffix.lower() in (".exe", ".dll"): s += 2
        s += int(p.stat().st_mtime) // 1000
        return s
    candidates.sort(key=score, reverse=True)
    return candidates[0]

def _best_target_out(work_dir: Path, bin_path: Path | None) -> Path | None:
    """Pick JSON only from the root of work/ (no recursion)."""
    stem = _norm(bin_path.stem) if bin_path else ""
    exacts = []
    for suffix in JSON_PATTERNS:
        if stem:
            p = work_dir / f"{bin_path.stem}{suffix}"
            if p.exists() and p.is_file():
                exacts.append(p)
        p = work_dir / suffix
        if p.exists() and p.is_file():
            exacts.append(p)
    if exacts:
        exacts.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return exacts[0]

    loose = [p for p in work_dir.glob("*")
             if p.is_file() and p.suffix.lower() == ".json" and "out" in p.name.lower()]
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

    bin_override = os.getenv("HUNT_BIN")
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

    funcs = _coerce_funcs(target)
    print(f"[hunt] functions discovered: {len(funcs)}")
    lim = os.getenv("HUNT_LIMIT")
    if lim and lim.isdigit():
        funcs = funcs[:int(lim)]
        print(f"[hunt] limiting to first {len(funcs)} functions due to HUNT_LIMIT")

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

