import json, os
from pathlib import Path

def write_report(labeled, out_dir):
    Path(out_dir).mkdir(exist_ok=True)
    md = ["# Function Hunt Report\n"]
    for L in labeled:
        md.append(f"## {L.get('name','unknown')}")
        md.append(f"**address:** `{L.get('_addr')}`  \n**confidence:** {L.get('confidence',0):.2f}")
        tags = ", ".join(L.get("tags", []))
        md.append(f"**tags:** {tags}")
        ev = L.get("evidence", [])
        if isinstance(ev, list):
            ev = "; ".join(ev[:6])
        md.append(f"**evidence:** {ev}")
        md.append("---\n")
    out = os.path.join(out_dir, "report.md")
    with open(out, "w") as f:
        f.write("\n".join(md))
    return out

