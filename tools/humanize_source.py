#!/usr/bin/env python3
# tools/humanize_source.py
import argparse, json, os, re, shutil, sys
from pathlib import Path
from typing import Dict, List, Tuple

PAIR_CANDIDATES = [
    ("_orig_name", "name"),
    ("name_orig", "name_human"),
    ("old", "new"),
    ("func_name", "suggested_name"),
    ("original", "proposed"),
    ("symbol", "name"),
]

VALID_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

def pairs_from_obj(obj: dict) -> Tuple[str, str] | None:
    for a, b in PAIR_CANDIDATES:
        if a in obj and b in obj:
            old = str(obj[a]).strip()
            new = str(obj[b]).strip()
            if old and new:
                return (old, new)
    # fallback: if only "name" exists, do nothing
    return None

def load_mapping(path: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    text = path.read_text(encoding="utf-8", errors="ignore")

    # Try JSON array/object
    objs: List[dict] = []
    try:
        data = json.loads(text)
        objs = data if isinstance(data, list) else [data]
    except Exception:
        # JSONL fallback
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except Exception:
                continue

    for obj in objs:
        if not isinstance(obj, dict):
            continue
        pair = pairs_from_obj(obj)
        if not pair:
            continue
        old, new = pair
        # sanitize identifiers
        if not VALID_IDENT.match(old):
            continue
        if not VALID_IDENT.match(new):
            new = re.sub(r"[^A-Za-z0-9_]", "_", new)
            if not VALID_IDENT.match(new):
                continue
        mapping[old] = new

    return mapping

def resolve_collisions(mapping: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    used: Dict[str, str] = {}
    for old, new in mapping.items():
        base = new
        i = 1
        while new in used and used[new] != old:
            i += 1
            new = f"{base}_{i}"
        used[new] = old
        out[old] = new
    return out

def compile_subs(mapping: Dict[str, str]) -> List[Tuple[re.Pattern, str, str]]:
    """
    Prepare list of (regex, replacement, old) entries.
    Use strict identifier boundaries to avoid partial replacements.
    """
    subs: List[Tuple[re.Pattern, str, str]] = []
    # longer names first to avoid overlaps
    for old in sorted(mapping.keys(), key=len, reverse=True):
        new = mapping[old]
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(old)}(?![A-Za-z0-9_])")
        subs.append((pattern, new, old))
    return subs

def rewrite_file_text(text: str, subs: List[Tuple[re.Pattern, str, str]]) -> Tuple[str, Dict[str, int]]:
    counts: Dict[str, int] = {}
    out = text
    for rx, new, old in subs:
        out, n = rx.subn(new, out)
        if n:
            counts[old] = counts.get(old, 0) + n
    return out, counts

def humanize_tree(src_dir: Path, out_dir: Path, mapping: Dict[str, str],
                  extensions=(".c", ".h"), dry_run=False) -> Dict[str, Dict[str, int]]:
    if not src_dir.exists():
        raise FileNotFoundError(src_dir)
    if not dry_run:
        if out_dir.exists():
            shutil.rmtree(out_dir)
        shutil.copytree(src_dir, out_dir)

    subs = compile_subs(mapping)
    files: List[Path] = []
    for ext in extensions:
        files.extend([p for p in out_dir.rglob(f"*{ext}")])

    total = len(files)
    summary: Dict[str, Dict[str, int]] = {}
    for i, path in enumerate(files, 1):
        text = path.read_text(encoding="utf-8", errors="ignore")
        new_text, counts = rewrite_file_text(text, subs)
        if not dry_run and new_text != text:
            path.write_text(new_text, encoding="utf-8")
        if counts:
            summary[str(path.relative_to(out_dir))] = counts
        if (i % max(1, total // 25) == 0) or (i == total):
            print(f"[humanize] progress {i}/{total}")
    return summary

def write_change_log(out_dir: Path, summary: Dict[str, Dict[str, int]], mapping: Dict[str, str]) -> None:
    logp = out_dir / "_humanize_changes.md"
    lines: List[str] = []
    lines.append("# Humanize Change Log\n")
    lines.append("## Rename mapping\n")
    for old, new in mapping.items():
        lines.append(f"- `{old}` → `{new}`")
    lines.append("\n## Per-file replacements\n")
    for f, counts in summary.items():
        lines.append(f"- **{f}**")
        for old, n in counts.items():
            lines.append(f"  - `{old}` → `{mapping.get(old,'?')}` : {n}")
        lines.append("")
    logp.write_text("\n".join(lines), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Humanize recovered C source by applying LLM-suggested function names")
    ap.add_argument("--src-dir", required=True, help="Path to recovered source (root containing .c/.h)")
    ap.add_argument("--out-dir", required=True, help="Path to write the humanized source tree")
    ap.add_argument("--mapping", required=True, help="JSON or JSONL with rename pairs")
    ap.add_argument("--ext", default=".c,.h", help="Comma-separated extensions to rewrite (default: .c,.h)")
    ap.add_argument("--dry-run", action="store_true", help="Don’t write files; just print a summary")
    args = ap.parse_args()

    src_dir = Path(args.src_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    mapping_path = Path(args.mapping).resolve()
    extensions = tuple(e if e.startswith(".") else f".{e}" for e in args.ext.split(","))

    mapping = load_mapping(mapping_path)
    if not mapping:
        print(f"[humanize] no valid rename pairs found in: {mapping_path}", file=sys.stderr)
        return 2

    mapping = resolve_collisions(mapping)
    summary = humanize_tree(src_dir, out_dir, mapping, extensions=extensions, dry_run=args.dry_run)

    print("[humanize] files changed:", len(summary))
    total_repl = sum(sum(c.values()) for c in summary.values())
    print("[humanize] total replacements:", total_repl)

    if not args.dry_run:
        write_change_log(out_dir, summary, mapping)
        print(f"[humanize] change log → {out_dir}/_humanize_changes.md")
    return 0

if __name__ == "__main__":
    sys.exit(main())

