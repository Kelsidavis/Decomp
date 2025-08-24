#!/usr/bin/env python3
# tools/function_hunt/report.py
from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict

HEADER = """# Function Hunt Report

Total functions labeled: {n}

This report is generated automatically. See `functions.labeled.jsonl` for the structured feed consumed by tooling (e.g., humanize_source.py).
"""

def _fmt_one(lab: Dict) -> str:
    name = lab.get("name", "unknown")
    addr = lab.get("_addr") or lab.get("address") or ""
    conf = lab.get("confidence", 0)
    tags = ", ".join(lab.get("tags", []))
    ev   = "; ".join(lab.get("evidence", []))
    return f"## {name} ({addr})\n- confidence: {conf}\n- tags: {tags}\n- evidence: {ev}\n"

def write_report(labeled: List[Dict], out_dir: str) -> str:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 1) Write the JSONL the humanizer expects
    jsonl_path = out / "functions.labeled.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as f:
        for lab in labeled:
            # Ensure minimal fields are present for downstream
            obj = dict(lab)
            if "_orig_name" not in obj and "orig_name" in obj:
                obj["_orig_name"] = obj["orig_name"]
            if "_addr" not in obj and "address" in obj:
                obj["_addr"] = obj.get("address")
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    # 2) (Optional) Write a small CSV mapping (handy for grepping)
    csv_path = out / "names_map.csv"
    with csv_path.open("w", encoding="utf-8") as f:
        f.write("address,old_name,new_name,confidence,tags\n")
        for lab in labeled:
            addr = lab.get("_addr") or lab.get("address") or ""
            oldn = (lab.get("_orig_name") or lab.get("orig_name") or "") or ""
            newn = lab.get("name", "")
            conf = lab.get("confidence", 0)
            tags = "|".join(lab.get("tags", []))
            # escape commas lightly
            def esc(x: str) -> str:
                return '"' + x.replace('"','""') + '"' if ("," in x or '"' in x or "|" in x) else x
            f.write(f"{esc(str(addr))},{esc(str(oldn))},{esc(str(newn))},{conf},{esc(tags)}\n")

    # 3) Human-readable markdown report
    md_path = out / "report.md"
    parts = [HEADER.format(n=len(labeled))]
    for lab in labeled[:500]:  # cap to keep file readable
        parts.append(_fmt_one(lab))
    md_path.write_text("\n".join(parts), encoding="utf-8")

    return str(md_path)

