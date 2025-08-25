#!/usr/bin/env python3
# tools/json_guard.py — validate/repair label JSON lines and stream them safely

from __future__ import annotations
import json, re
from typing import Dict, Any, Iterable, Iterator, Optional
from pathlib import Path

# ---- helpers -------------------------------------------------

def _strip_code_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = s.split("```", 1)[-1]
        if "```" in s:
            s = s.rsplit("```", 1)[0]
    return s.strip()

def _extract_balanced(text: str) -> Optional[str]:
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0: start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    return text[start:i+1]
    return None

def _as_list(v) -> list[str]:
    if v is None: return []
    if isinstance(v, list): return [str(x)[:256] for x in v]
    return [str(v)[:256]]

def _coerce_float(x, default=0.5) -> float:
    try: return float(x)
    except Exception: return float(default)

# ---- public --------------------------------------------------

def sanitize_label(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a raw label dict into a safe, predictable schema."""
    out: Dict[str, Any] = {}
    out["name"]         = (str(obj.get("name")) if obj.get("name") is not None else "unknown")[:128]
    out["tags"]         = _as_list(obj.get("tags"))
    out["inputs"]       = _as_list(obj.get("inputs"))
    out["outputs"]      = _as_list(obj.get("outputs"))
    out["side_effects"] = _as_list(obj.get("side_effects"))
    ev                  = obj.get("evidence")
    if isinstance(ev, list): out["evidence"] = [str(x)[:512] for x in ev]
    elif ev is None:         out["evidence"] = []
    else:                    out["evidence"] = [str(ev)[:512]]
    out["confidence"]   = _coerce_float(obj.get("confidence", 0.5), 0.5)
    # carry metadata if present
    if "_addr" in obj:      out["_addr"] = obj["_addr"]
    if "_orig_name" in obj: out["_orig_name"] = obj["_orig_name"]
    return out

def _try_parse(line: str) -> Optional[Dict[str, Any]]:
    """Best-effort parse for a single line possibly containing JSON with noise."""
    line = line.strip()
    if not line: return None
    # try direct
    try: return json.loads(line)
    except Exception: pass
    # fenced
    try:
        cf = _strip_code_fences(line)
        if cf and cf != line:
            return json.loads(cf)
    except Exception: pass
    # balanced
    try:
        bal = _extract_balanced(line)
        if bal:
            return json.loads(bal)
    except Exception: pass
    return None

def load_labels_stream(path: str | Path, *, write_repaired: bool = True) -> Iterator[Dict[str, Any]]:
    """
    Stream sanitized labels from JSONL. Repairs rows when needed.
    If write_repaired, also writes a cleaned mirror at *.repaired.jsonl next to the original.
    """
    p = Path(path)
    if not p.exists():
        return iter(())
    # Create repaired sink if desired
    sink = None
    if write_repaired:
        sink = p.with_suffix(p.suffix + ".repaired.jsonl")
        f = sink.open("w", encoding="utf-8")
        f.close()

    seen = set()  # dedupe by (_addr, _orig_name, name)
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            obj = _try_parse(raw)
            if obj is None:
                # fabricate a minimal record to keep pipeline flowing
                obj = {"name":"unknown","tags":[],"inputs":[],"outputs":[],"side_effects":[],"confidence":0.3,"evidence":["invalid_json_line"]}
            clean = sanitize_label(obj)
            key = (str(clean.get("_addr")), str(clean.get("_orig_name")), clean["name"])
            if key in seen:
                continue
            seen.add(key)
            if write_repaired:
                try:
                    with sink.open("a", encoding="utf-8") as out:
                        out.write(json.dumps(clean, ensure_ascii=False) + "\n")
                except Exception:
                    pass
            yield clean

