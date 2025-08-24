#!/usr/bin/env python3
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

def load_mapping(path: Path) -> Dict[str, str]:
    """Load JSON or JSONL mapping and return {old_name: new_name}."""
    if not path.exists():
        raise FileNotFoundError(path)

    def pairs_from_obj(obj: dict) -> Tuple[str, str] | None:
        for k_old, k_new in PAIR_CANDIDATES:
            if k_old in obj and k_new in obj:
                old, new = str(obj[k_old]).strip(), str(obj[k_new]).strip()
                if old and new:
                    return old, new
        # fallback: some labelers produce {"_orig_name": "...", "label":{"name": "..."}}
        if "_orig_name" in obj and isinstance(obj.get("label"), dict) and "name" in obj["label"]:
            return str(obj["_orig_name"]).strip(), str(obj["label"]["name"]).strip()
        return None

    mapping: Dict[str, str] = {}
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(text)
        objs = data if isinstance(data, list) else [data]
    except Exception:
        # assume JSONL
        objs = []
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
        # sanitize: only keep valid C identifiers; coerce proposed names by replacing bad chars with '_'
        if not VALID_IDENT.match(old):
            # allow typical sub/FUN names; if not valid ident, skip
            continue
        if not VALID_IDENT.match(new):
            new = re.sub(r"[^A-Za-z0-9_]", "_", new)
            if not VALID_IDENT.match(new):
                continue
        mapping[old] = new

    return mapping

def resolve_collisions(mapping: Dict[str, str]) -> Dict[str, str]:
    """Ensure new names are unique; append numeric suffixes if necessary."""
    used = {}
    out = {}
    for old, new in mapping.items():
        base = new
        i = 1
        while used.get(new, None) not in (None, old):
            i += 1
            new = f"{base}_{i}"
        used[new] = old
        out[old] = new
    return out

def compile_subs(mapping: Dict[str, str]) -> List[Tuple[re.Pattern, str, str]]:
    """
    Prepare list of (regex, replacement, old) entries.
    We use word-boundary \b replacement to avoid touching substrings.
    """
    subs = []
    # Sort by descending length to avoid partial overlaps (e.g., FUN_4012 and FUN_4012a0)
    for old in sorted(mapping.keys(), key=len, reverse=True):
        new = mapping[old]
        # \b doesn't match underscores well on the right; enforce identifier boundaries manually
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(old)}(?![A-Za-z0-9_])")
        subs.append((pattern, new, old))
    return subs

def rewrite_file_text(text: str, subs: List[Tuple[re.Pattern, str, str]]) -> Tuple[str, Dict[str, int]]:
    counts: Dict[str, int] = {}
    for rx, new, old in subs:
        text, n = rx.subn(new, text)
        if n:
            counts[old] = counts.get(old, 0) + n
    return text, counts

def humanize_tree(src_dir: Path, out_dir: Path, mapping: Dict[str, str],
                  extensions=(".c", ".h"), dry_run=False) -> Dict[str, Dict[str, int]]:
    if not src_dir.exists():
        raise FileNotFoundError(src_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    subs = compile_subs(mapping)
    summary: Dict[str, Dict[str, int]] = {}

    # Copy tree first (so we don't touch originals), then rewrite eligible files
    if not dry_run:
        if out_dir.exists():
            # keep existing files; we overwrite per-file
            pass

    for src in src_dir.rglob("*"):
        rel = src.relative_to(src_dir)
        dst = out_dir / rel
        if src.is_dir():
            dst.mkdir(exist_ok=True)
            continue
        # always copy files (to have a complete tree); then possibly rewrite
        if not dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

        if src.suffix.lower() not in extensions:
            continue

        text = src.read_text(encoding="utf-8", errors="ignore")
        new_text, counts = rewrite_file_text(text, subs)

        if counts:
            summary[str(rel)] = counts
            if not dry_run:
                dst.write_text(new_text, encoding="utf-8")

    return summary

def write_change_log(out_dir: Path, summary: Dict[str, Dict[str, int]], mapping: Dict[str, str]):
    logp = out_dir / "_humanize_changes.md"
    lines = ["# Humanize Source – Changes\n"]
    lines.append("## Rename mapping (after collision resolution)\n")
    for old, new in sorted(mapping.items()):
        lines.append(f"- `{old}` → `{new}`")
    lines.append("\n## Per-file replacements\n")
    for file, counts in sorted(summary.items()):
        total = sum(counts.values())
        lines.append(f"### {file}  (total {total})")
        for old, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- `{old}` → `{mapping.get(old,'?')}` : {n}")
        lines.append("")
    logp.write_text("\n".join(lines), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser("Humanize recovered C source by applying LLM-suggested function names")
    ap.add_argument("--src-dir", required=True, help="Path to original recovered source (root containing .c/.h)")
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

