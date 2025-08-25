#!/usr/bin/env python3
"""
Humanize recovered C source by applying LLM-suggested function names.

Features:
- Auto-resume (HUMANIZE_RESUME=1): tracks index in work/humanize.progress; skips already-processed files.
- Progress lines: "[humanize] progress d/t | ...".
- Robust mapping load via json_guard.load_labels_stream with auto-repair.
- Regex-safe renames for function identifiers:
    • Calls/defs/prototypes:   sub_XXXX(... )
    • Func-pointer declarators: (*sub_XXXX)
- Optional AST-assisted mode (HUMANIZE_AST=1) via pycparser:
    • Parses each file (with fake libc includes) to discover which function names
      actually appear as decl/def/call in that file; refines rename set per-file.
    • Falls back to regex-only if parsing fails (no crash).

Environment:
  HUMANIZE_AST=1           -> enable AST-assisted refinement (default off)
  WORK_DIR=work            -> base for progress file
"""

from __future__ import annotations
import os, re, sys, shutil, time, argparse
from pathlib import Path
from typing import Dict, Any, List, Tuple, Iterable, Set, Optional

# ------------- toggles & paths -------------
HUMANIZE_AST = os.getenv("HUMANIZE_AST","0").lower() in ("1","true","yes","on")
WORK_DIR     = Path(os.getenv("WORK_DIR","work"))
PROGRESS_FILE = WORK_DIR / "humanize.progress"

# ------------- mapping load (guarded) -------------
def load_mapping_stream(mapping_path: Path) -> Iterable[Dict[str,Any]]:
    try:
        from json_guard import load_labels_stream
        return load_labels_stream(mapping_path)
    except Exception:
        # fallback: naive line-by-line load (repair minimal)
        def _raw_lines():
            with mapping_path.open("r",encoding="utf-8",errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln: continue
                    import json
                    try:
                        yield json.loads(ln)
                    except Exception:
                        yield {"name":"unknown","confidence":0.3,"evidence":["invalid_json"]}
        return _raw_lines()

def build_rename_map(mapping_path: Path) -> Dict[str,str]:
    rename: Dict[str,str] = {}
    for rec in load_mapping_stream(mapping_path):
        old = str(rec.get("_orig_name") or "").strip()
        new = str(rec.get("name") or "").strip()
        if not old or not new or old == new:
            continue
        # C identifier sanity
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", new):
            continue
        rename[old] = new
    return rename

# ------------- regex renamer -------------
def rename_in_text(text: str, rename: Dict[str,str]) -> Tuple[str,int]:
    """
    Replace function identifiers in:
      - calls/defs/prototypes:   foo(
      - func-pointer declarators: (*foo)
    NOTE: We intentionally avoid general ID renames to not touch variables/macros.
    """
    count = 0
    for old, new in rename.items():
        # calls/defs/prototypes: foo(
        pat1 = re.compile(rf"\b{re.escape(old)}\b(?=\s*\()", flags=re.MULTILINE)
        text, n1 = pat1.subn(new, text)
        # function pointer declarators: (*foo)
        # keep inner spacing; only swap the identifier
        pat2 = re.compile(rf"\(\s*\*{re.escape(old)}\s*\)", flags=re.MULTILINE)
        text, n2 = pat2.subn(lambda m: m.group(0).replace(old, new), text)
        count += (n1 + n2)
    return text, count

# ------------- file helpers -------------
def list_source_files(src_dir: Path, exts: Tuple[str,...]=(".c",".h")) -> List[Path]:
    files: List[Path] = []
    for ext in exts:
        files.extend(src_dir.rglob(f"*{ext}"))
    files.sort()
    return files

def ensure_out_path(out_dir: Path, src_root: Path, src_file: Path) -> Path:
    rel = src_file.relative_to(src_root)
    dest = out_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    return dest

def read_progress() -> int:
    if not PROGRESS_FILE.exists(): return -1
    try:
        return int(PROGRESS_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return -1

def write_progress(i: int) -> None:
    try:
        PROGRESS_FILE.write_text(str(i), encoding="utf-8")
    except Exception:
        pass

def clear_progress() -> None:
    try:
        if PROGRESS_FILE.exists(): PROGRESS_FILE.unlink()
    except Exception:
        pass

# ------------- AST-assisted refinement -------------
def _pycparser_fake_inc() -> Optional[str]:
    """Locate pycparser's fake_libc_include directory if available."""
    try:
        import pycparser, os as _os
        base = _os.path.dirname(pycparser.__file__)
        cand = _os.path.join(base, "utils", "fake_libc_include")
        return cand if os.path.isdir(cand) else None
    except Exception:
        return None

def _collect_names_ast(src_path: Path, exts: Tuple[str,...]) -> Set[str]:
    """
    Parse a C file with pycparser and collect function identifiers that appear as:
      - function definitions / prototypes (Decl/FuncDecl)
      - callee names in function calls (FuncCall with ID)
      - function pointer declarators (Decl with PtrDecl->FuncDecl)
    Returns a set of identifier names found in these contexts.
    """
    names: Set[str] = set()
    try:
        from pycparser import c_ast, parse_file
    except Exception:
        return names  # pycparser not available

    fake = _pycparser_fake_inc()
    cpp_args = []
    if fake:
        cpp_args = [f'-I{fake}']
    try:
        ast = parse_file(
            str(src_path),
            use_cpp=True,
            cpp_path='cpp' if os.name != 'nt' else 'clang',
            cpp_args=cpp_args
        )
    except Exception:
        # If preprocessing fails (macros/headers), give up gracefully
        return names

    class Visitor(c_ast.NodeVisitor):  # type: ignore
        def visit_Decl(self, node: "c_ast.Decl"):  # type: ignore
            # Any declaration whose type resolves to FuncDecl, possibly through PtrDecl
            t = node.type
            is_func_decl = False
            while t is not None:
                if t.__class__.__name__ == "FuncDecl":
                    is_func_decl = True
                    break
                t = getattr(t, "type", None)
            if is_func_decl and node.name:
                names.add(str(node.name))
            # continue traversal
            self.generic_visit(node)

        def visit_FuncDef(self, node: "c_ast.FuncDef"):  # type: ignore
            try:
                dn = node.decl.name
                if dn: names.add(str(dn))
            except Exception:
                pass
            self.generic_visit(node)

        def visit_FuncCall(self, node: "c_ast.FuncCall"):  # type: ignore
            try:
                callee = node.name
                # Direct ID call: foo(...)
                if hasattr(callee, "name"):
                    nm = getattr(callee, "name", None)
                    if nm: names.add(str(nm))
            except Exception:
                pass
            self.generic_visit(node)

    try:
        Visitor().visit(ast)
    except Exception:
        # AST traversal failed — ignore
        return names

    return names

def refine_rename_for_file(src_path: Path, rename_global: Dict[str,str], exts: Tuple[str,...]) -> Dict[str,str]:
    """
    If HUMANIZE_AST=1 and pycparser works, filter the rename map to only names
    that appear in decl/def/call contexts within this file.
    Otherwise, return the global rename map (regex-only behavior).
    """
    if not HUMANIZE_AST:
        return rename_global

    # Collect eligible names in this file via AST
    names_in_file = _collect_names_ast(src_path, exts)
    if not names_in_file:
        # AST failed or found none; fall back to global (regex-only)
        return rename_global

    # Filter to the subset
    subset = {old:new for old,new in rename_global.items() if old in names_in_file}
    # If AST subset ends up empty (e.g., AST missed due to macros), fall back to global
    return subset or rename_global

# ------------- main -------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Humanize recovered C source by applying LLM-suggested function names")
    ap.add_argument("--src-dir", required=True, help="Input source tree (recovered_project/src)")
    ap.add_argument("--out-dir", required=True, help="Output tree for humanized source")
    ap.add_argument("--mapping", required=True, help="functions.labeled.jsonl")
    ap.add_argument("--ext", default=".c,.h", help="Comma-separated extensions to process (default: .c,.h)")
    ap.add_argument("--dry-run", action="store_true", help="Do not write files")
    args = ap.parse_args()

    src_dir = Path(args.src_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    mapping = Path(args.mapping).resolve()
    exts = tuple([e if e.startswith(".") else f".{e}" for e in args.ext.split(",") if e.strip()])

    if not src_dir.exists():
        print(f"[humanize] src not found: {src_dir}")
        return 1
    if not mapping.exists():
        print(f"[humanize] mapping not found: {mapping}")
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)

    # build global rename map with guard
    rename_global = build_rename_map(mapping)
    if not rename_global:
        print("[humanize] no renames in mapping (nothing to do)")
        # still mirror tree to out_dir for consistency
        if not args.dry_run:
            for p in list_source_files(src_dir, exts):
                dst = ensure_out_path(out_dir, src_dir, p)
                if not dst.exists():
                    shutil.copy2(p, dst)
        return 0

    files = list_source_files(src_dir, exts)
    total = len(files)
    if total == 0:
        print("[humanize] no source files found")
        return 0

    resume = os.getenv("HUMANIZE_RESUME","1").lower() in ("1","true","yes","on")
    start_idx = read_progress() if resume else -1
    done = max(0, start_idx + 1)
    t0 = time.time()

    for i, src in enumerate(files):
        if i <= start_idx:
            continue
        dst = ensure_out_path(out_dir, src_dir, src)

        # skip if resume and already processed newer than inputs
        if resume and dst.exists():
            try:
                if dst.stat().st_mtime >= max(src.stat().st_mtime, mapping.stat().st_mtime):
                    write_progress(i)
                    done += 1
                    pct = int(100 * done / total)
                    elapsed = int(time.time() - t0)
                    print(f"[humanize] progress {done}/{total} | {pct}% | elapsed {elapsed}s")
                    continue
            except Exception:
                pass

        text = src.read_text(encoding="utf-8", errors="ignore")

        # AST-assisted per-file refinement (graceful fallback inside)
        local_map = refine_rename_for_file(src, rename_global, exts)

        new_text, n = rename_in_text(text, local_map)

        if args.dry_run:
            pass
        else:
            if new_text == text:
                # mirror to keep output tree complete
                shutil.copy2(src, dst)
            else:
                dst.write_text(new_text, encoding="utf-8")

        write_progress(i)
        done += 1
        pct = int(100 * done / total)
        elapsed = int(time.time() - t0)
        mode = "AST" if HUMANIZE_AST else "regex"
        print(f"[humanize] progress {done}/{total} | {pct}% | elapsed {elapsed}s (renamed {n}, mode={mode})")

    clear_progress()
    print(f"[humanize] wrote: {out_dir}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

