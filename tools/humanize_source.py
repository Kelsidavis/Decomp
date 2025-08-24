#!/usr/bin/env python3
# tools/humanize_source.py
import argparse, json, os, re, shutil, sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional

HUMANIZE_AST_OPT = os.getenv("HUMANIZE_AST", "1").lower() in ("1","true","yes","on")

PAIR_CANDIDATES = [
    ("_orig_name", "name"),
    ("name_orig", "name_human"),
    ("old", "new"),
    ("func_name", "suggested_name"),
    ("original", "proposed"),
    ("symbol", "name"),
]

VALID_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# ---- optional pycparser import ----
PARSER_OK = False
try:
    if HUMANIZE_AST_OPT:
        from pycparser import c_parser, c_ast, c_generator  # type: ignore
        PARSER_OK = True
except Exception:
    PARSER_OK = False

def pairs_from_obj(obj: dict) -> Tuple[str, str] | None:
    for a, b in PAIR_CANDIDATES:
        if a in obj and b in obj:
            old = str(obj[a]).strip()
            new = str(obj[b]).strip()
            if old and new:
                return (old, new)
    return None

def load_labels_and_mapping(path: Path) -> Tuple[Dict[str, str], Dict[str, dict]]:
    """
    Returns:
      mapping: {old_name -> new_name}
      labelinfo: {new_name -> full_label_object}
    """
    mapping: Dict[str, str] = {}
    labelinfo: Dict[str, dict] = {}
    text = path.read_text(encoding="utf-8", errors="ignore")

    objs: List[dict] = []
    try:
        data = json.loads(text)
        objs = data if isinstance(data, list) else [data]
    except Exception:
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
        if not VALID_IDENT.match(old):
            continue
        new_sane = re.sub(r"[^A-Za-z0-9_]", "_", new)
        if not VALID_IDENT.match(new_sane):
            continue
        mapping[old] = new_sane
        labelinfo[new_sane] = obj  # keyed by final name for convenience

    return mapping, labelinfo

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
    subs: List[Tuple[re.Pattern, str, str]] = []
    for old in sorted(mapping.keys(), key=len, reverse=True):
        new = mapping[old]
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(old)}(?![A-Za-z0-9_])")
        subs.append((pattern, new, old))
    return subs

def rewrite_file_text_regex(text: str, subs: List[Tuple[re.Pattern, str, str]]) -> Tuple[str, Dict[str, int]]:
    counts: Dict[str, int] = {}
    out = text
    for rx, new, old in subs:
        out, n = rx.subn(new, out)
        if n:
            counts[old] = counts.get(old, 0) + n
    return out, counts

# ---- Heuristics for parameter naming ----
BAD_PARAM = re.compile(r"^(?:v\d+|a\d+|arg\d+|param\d+|__?\w+)$", re.I)
def _guess_param_name(ctype: str, idx: int, hints_in: List[str], hints_out: List[str]) -> str:
    # try hints first
    if idx < len(hints_in):
        candidate = re.sub(r"[^A-Za-z0-9_]", "_", hints_in[idx])[:32]
        if VALID_IDENT.match(candidate): return candidate
    # heuristic by type
    t = ctype.lower()
    if "*" in t:
        # pointer types
        for cand in ("buf", "dst", "src", "data", "out", "ptr", "ctx"):
            return cand if idx == 0 else f"{cand}{idx+1}"
    if "size" in t or "len" in t:
        return "len" if idx == 0 else f"len{idx+1}"
    if "count" in t or "n" == t or "num" in t:
        return "count" if idx == 0 else f"count{idx+1}"
    if "handle" in t or "hwnd" in t or "context" in t or "ctx" in t:
        return "ctx" if idx == 0 else f"ctx{idx+1}"
    if "file" in t or "path" in t:
        return "path" if idx == 0 else f"path{idx+1}"
    if "flag" in t:
        return "flags" if idx == 0 else f"flags{idx+1}"
    # generic fallback
    return f"arg{idx+1}"

def _apply_param_names_pyc(parser, generator, code: str, rename_map: Dict[str,str], labelinfo: Dict[str,dict]) -> Optional[str]:
    """
    Parse with pycparser, rename functions, and improve parameter names
    for functions that got renamed. Returns None if parsing fails.
    """
    try:
        ast = parser.parse(code)
    except Exception:
        return None

    class Renamer(c_ast.NodeVisitor):  # type: ignore
        def visit_FuncDef(self, node: "c_ast.FuncDef"):  # type: ignore
            # rename function identifier
            if isinstance(node.decl, c_ast.Decl) and isinstance(node.decl.type, c_ast.FuncDecl):
                old_name = node.decl.name
                if old_name in rename_map:
                    node.decl.name = rename_map[old_name]
                # param naming
                ftype = node.decl.type
                params = getattr(getattr(ftype, "args", None), "params", []) or []
                hints = labelinfo.get(rename_map.get(old_name, old_name), {})
                hin = list(hints.get("inputs") or [])
                hout = list(hints.get("outputs") or [])
                for i, p in enumerate(params):
                    if not isinstance(p, c_ast.Decl):  # type: ignore
                        continue
                    # current param name/type
                    pname = p.name or f"arg{i+1}"
                    ptype = p.type.type.names if hasattr(p.type, "type") and hasattr(p.type.type, "names") else []
                    ctype = " ".join(ptype) if isinstance(ptype, list) else str(ptype)
                    if BAD_PARAM.match(pname) or not VALID_IDENT.match(pname):
                        newp = _guess_param_name(ctype, i, hin, hout)
                        p.name = newp

        def visit_Decl(self, node: "c_ast.Decl"):  # type: ignore
            # rename function declarations (prototypes)
            if isinstance(node.type, c_ast.FuncDecl):  # type: ignore
                old_name = node.name
                if old_name in rename_map:
                    node.name = rename_map[old_name]

        def visit_FuncCall(self, node: "c_ast.FuncCall"):  # type: ignore
            # rename call sites
            if isinstance(node.name, c_ast.ID):  # type: ignore
                name = node.name.name
                if name in rename_map:
                    node.name.name = rename_map[name]

    Renamer().visit(ast)
    try:
        return generator.visit(ast)
    except Exception:
        return None

def humanize_tree_ast(src_dir: Path, out_dir: Path, mapping: Dict[str, str], labelinfo: Dict[str,dict]) -> Tuple[int,int]:
    parser = c_parser.CParser()
    generator = c_generator.CGenerator()
    changed_files = 0
    total_repl = 0

    for path in src_dir.rglob("*.c"):
        code = path.read_text(encoding="utf-8", errors="ignore")
        new_code = _apply_param_names_pyc(parser, generator, code, mapping, labelinfo)
        if new_code is None:
            # fallback to regex if this file fails to parse
            subs = compile_subs(mapping)
            new_code, counts = rewrite_file_text_regex(code, subs)
            total_repl += sum(counts.values())
        else:
            # rough replacement counts (best effort)
            cnt = 0
            for old, new in mapping.items():
                if old == new: continue
                cnt += len(re.findall(rf"(?<![A-Za-z0-9_]){re.escape(new)}(?![A-Za-z0-9_])", new_code))
            total_repl += cnt

        out_path = out_dir / path.relative_to(src_dir)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(new_code, encoding="utf-8")
        changed_files += 1
        if changed_files % 20 == 0:
            print(f"[humanize] progress {changed_files}/?", flush=True)

    return changed_files, total_repl

def humanize_tree_regex(src_dir: Path, out_dir: Path, mapping: Dict[str, str]) -> Tuple[int,int]:
    subs = compile_subs(mapping)
    files = [p for p in src_dir.rglob("*.c")] + [p for p in src_dir.rglob("*.h")]
    changed_files = 0
    total = len(files)
    total_repl = 0

    for i, path in enumerate(files, 1):
        text = path.read_text(encoding="utf-8", errors="ignore")
        new_text, counts = rewrite_file_text_regex(text, subs)
        if new_text != text:
            out_path = out_dir / path.relative_to(src_dir)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(new_text, encoding="utf-8")
        else:
            out_path = out_dir / path.relative_to(src_dir)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding="utf-8")

        total_repl += sum(counts.values())
        changed_files += 1
        if (i % max(1, total // 25) == 0) or (i == total):
            print(f"[humanize] progress {i}/{total}")
    return changed_files, total_repl

def write_change_log(out_dir: Path, mapping: Dict[str, str], changed_files: int, total_repl: int) -> None:
    logp = out_dir / "_humanize_changes.md"
    lines: List[str] = []
    lines.append("# Humanize Change Log\n")
    lines.append("## Rename mapping\n")
    for old, new in mapping.items():
        lines.append(f"- `{old}` → `{new}`")
    lines.append(f"\nFiles changed: {changed_files}\n")
    lines.append(f"Approximate replacements: {total_repl}\n")
    logp.write_text("\n".join(lines), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Humanize recovered C source by applying LLM-suggested function names")
    ap.add_argument("--src-dir", required=True, help="Path to recovered source (root containing .c/.h)")
    ap.add_argument("--out-dir", required=True, help="Path to write the humanized source tree")
    ap.add_argument("--mapping", required=True, help="JSON or JSONL with rename pairs")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    src_dir = Path(args.src_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    mapping_path = Path(args.mapping).resolve()

    # load mapping + labels for param hints
    mapping, labelinfo = load_labels_and_mapping(mapping_path)
    if not mapping:
        print(f"[humanize] no valid rename pairs found in: {mapping_path}", file=sys.stderr)
        return 2
    mapping = resolve_collisions(mapping)

    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(src_dir, out_dir)

    if PARSER_OK:
        changed, repl = humanize_tree_ast(src_dir, out_dir, mapping, labelinfo)
    else:
        changed, repl = humanize_tree_regex(src_dir, out_dir, mapping)

    write_change_log(out_dir, mapping, changed, repl)
    print("[humanize] files changed:", changed)
    print("[humanize] approx replacements:", repl)
    return 0

if __name__ == "__main__":
    sys.exit(main())

