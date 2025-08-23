#!/usr/bin/env python3
"""
humanize_project.py

Take a 'recovered_project' produced by the pipeline and:
 - Parse report.md + out.json for hints
 - Propose human-friendly function names based on summaries/keywords
 - Emit NAME_SUGGESTIONS.yaml for review
 - Optionally apply the renames across include/recovered.h and src/*.c
 - Cluster functions into modules (net/crypto/fs/mem/os/ui/str/etc.) and move files
 - Generate docs/overview.md and docs/callgraph.dot (Graphviz)

Usage:
  python3 humanize_project.py /path/to/recovered_project \
    --out /path/to/recovered_project_human \
    --outjson /path/to/target_out.json \
    [--apply] [--lang c|cpp]

Recommended flow:
  1) Run without --apply; inspect NAME_SUGGESTIONS.yaml
  2) Re-run with --apply to actually rename & reorganize
"""

import argparse, os, re, shutil, pathlib, json, textwrap, yaml
from collections import defaultdict, Counter

H2_RE = re.compile(r'^\s*##\s+(.+?)(?:\s*\((0x[0-9A-Fa-f]+)\))?\s*$', re.M)

MODULE_KEYWORDS = {
    "net":   ["socket","tcp","udp","http","dns","tls","ssl","connect","send","recv","network"],
    "crypto":["aes","sha","md5","rsa","ecc","curve","cipher","decrypt","encrypt","hmac","key","nonce","iv"],
    "fs":    ["file","read","write","fopen","fclose","mkdir","unlink","stat","path"],
    "mem":   ["alloc","free","memcpy","memset","realloc","heap","stack"],
    "os":    ["thread","mutex","process","pid","env","registry","syscall","sleep","time","winapi","pe"],
    "ui":    ["window","dialog","button","menu","icon","bitmap","resource","gui"],
    "str":   ["string","strcpy","strlen","format","utf","wide","parse","token"],
    "zip":   ["zip","inflate","deflate","zlib","gzip","archive"],
    "db":    ["sqlite","sql","query","cursor","table"],
    "img":   ["png","jpeg","bmp","gif","webp","image"],
}

SAFE_PREFIXES = ["func_", "sub_", "_", "FUN_", "FUN", "nullsub_"]

def load_report_functions(report_md: str):
    """Return list of (name, addr, summary_text) from H2 sections."""
    out = []
    for m in H2_RE.finditer(report_md):
        name = m.group(1).strip()
        addr = m.group(2) or ""
        # grab the paragraph after header as summary-ish
        start = m.end()
        next_h2 = H2_RE.search(report_md, start)
        body = report_md[start: next_h2.start() if next_h2 else len(report_md)]
        # first non-empty paragraph lines (~summary)
        lines = [ln.strip() for ln in body.splitlines()]
        first_para = []
        for ln in lines:
            if ln:
                first_para.append(ln)
            elif first_para:
                break
        summary = " ".join(first_para)[:800]
        out.append((name, addr, summary))
    return out

def is_auto_name(name: str):
    n = name.lower()
    return any(n.startswith(p) for p in SAFE_PREFIXES) or re.fullmatch(r"sub_[0-9a-f]+", n) or re.fullmatch(r"loc_[0-9a-f]+", n)

def suggest_name(name: str, summary: str):
    """Heuristic rename: keep decent names; otherwise, synthesize from summary + address."""
    if not is_auto_name(name):
        return name  # already human-ish
    s = summary.lower()
    # look for strong hints
    buckets = []
    for mod, kws in MODULE_KEYWORDS.items():
        if any(kw in s for kw in kws):
            buckets.append(mod)
    core = None
    if "http" in s: core = "http"
    elif "socket" in s or "connect" in s or "send" in s or "recv" in s: core = "net"
    elif "decrypt" in s or "encrypt" in s or "cipher" in s or "aes" in s: core = "crypto"
    elif "file" in s or "path" in s or "read" in s or "write" in s: core = "fs"
    elif "string" in s or "utf" in s or "format" in s or "parse" in s: core = "str"
    elif "thread" in s or "mutex" in s: core = "os"
    elif "bitmap" in s or "icon" in s or "resource" in s: core = "ui"
    elif "sqlite" in s: core = "db"
    elif "zip" in s or "inflate" in s: core = "zip"
    elif "png" in s or "jpeg" in s or "bmp" in s: core = "img"

    if core:
        return f"{core}_{re.sub(r'[^a-z0-9]+','_', (summary.split('.')[0] or core))[:24]}".strip("_")
    # fallback: keep original
    return name

def cluster_module(name: str, summary: str):
    s = summary.lower()
    for mod, kws in MODULE_KEYWORDS.items():
        if any(kw in s for kw in kws):
            return mod
    return "misc"

def sanitize_ident(name: str):
    n = re.sub(r'[^A-Za-z0-9_]', '_', name)
    if not re.match(r'[A-Za-z_]', n):
        n = "f_" + n
    return n

def rewrite_ident_in_text(text: str, old: str, new: str):
    # whole-word rename (C ident boundaries)
    pat = re.compile(rf'\b{re.escape(old)}\b')
    return pat.sub(new, text)

def load_out_json_callers(out_json_path: pathlib.Path):
    callers = defaultdict(set)  # func -> callers set
    callees = defaultdict(set)  # caller -> callee set (approx via names in "callers")
    if not out_json_path.exists():
        return callers, callees
    with open(out_json_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            fname = obj.get("function_name") or ""
            for c in obj.get("callers", []):
                callers[fname].add(c)
                callees[c].add(fname)
    return callers, callees

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("project", help="Path to recovered_project")
    ap.add_argument("--out", default=None, help="Output dir (default: project + _human)")
    ap.add_argument("--outjson", default=None, help="Path to out.json (for callgraph)")
    ap.add_argument("--apply", action="store_true", help="Apply renames & module moves")
    ap.add_argument("--lang", choices=["c","cpp"], default="c")
    args = ap.parse_args()

    proj = pathlib.Path(args.project)
    inc = proj / "include"
    src = proj / "src"
    assets = proj / "assets"
    report_md_path = proj / "report.md"

    if not report_md_path.exists():
        raise SystemExit("report.md not found in project")
    if not inc.exists() or not src.exists():
        raise SystemExit("include/ or src/ missing in project")

    outdir = pathlib.Path(args.out or (str(proj) + "_human"))
    if outdir.exists():
        shutil.rmtree(outdir)
    shutil.copytree(proj, outdir)
    inc = outdir / "include"
    src = outdir / "src"
    assets = outdir / "assets"

    # Load report for names & summaries
    report = report_md_path.read_text(encoding="utf-8", errors="ignore")
    funcs = load_report_functions(report)  # (name, addr, summary)

    # Build suggestions
    suggestions = []
    for name, addr, summary in funcs:
        newname = sanitize_ident(suggest_name(name, summary))
        suggestions.append({
            "original": name,
            "suggested": newname,
            "address": addr,
            "reason": summary[:200]
        })

    # Dedup by preferring first occurrence
    seen = set()
    uniq = []
    for s in suggestions:
        key = s["original"]
        if key in seen: continue
        seen.add(key)
        uniq.append(suggestions[suggestions.index(s)])

    # Write suggestions YAML
    names_yaml = outdir / "NAME_SUGGESTIONS.yaml"
    with open(names_yaml, "w", encoding="utf-8") as w:
        yaml.safe_dump({"suggestions": uniq}, w, sort_keys=False, allow_unicode=True)

    # Module clustering
    mod_map = {}
    for name, addr, summary in funcs:
        mod_map[name] = cluster_module(name, summary)
    modules_yaml = outdir / "MODULES.yaml"
    with open(modules_yaml, "w", encoding="utf-8") as w:
        yaml.safe_dump({"modules": mod_map}, w, sort_keys=False, allow_unicode=True)

    # Optionally apply renames & move files into modules
    if args.apply:
        # Load headers & sources
        recovered_h = (inc / "recovered.h").read_text(encoding="utf-8", errors="ignore")
        sources = {}
        for p in src.glob("*.c" if args.lang=="c" else "*.cpp"):
            sources[p] = p.read_text(encoding="utf-8", errors="ignore")

        # Build rename mapping (skip if suggested equals original)
        rename = { s["original"]: s["suggested"] for s in uniq if s["suggested"] and s["suggested"] != s["original"] }

        # Apply to header
        for old, new in rename.items():
            recovered_h = rewrite_ident_in_text(recovered_h, old, new)
        (inc / "recovered.h").write_text(recovered_h, encoding="utf-8")

        # Apply to source files + rename filenames
        for p, text in list(sources.items()):
            newtext = text
            for old, new in rename.items():
                newtext = rewrite_ident_in_text(newtext, old, new)
            # If the file is named func_<old>.c, rename it accordingly
            m = re.match(r'func_(.+)\.(c|cpp)$', p.name)
            newpath = p
            if m:
                oldbase = m.group(1)
                # try to map to a function inside file
                for old, new in rename.items():
                    if oldbase in old or old.lower()==oldbase.lower():
                        newbase = sanitize_ident(new)
                        newpath = p.with_name(f"func_{newbase}.{m.group(2)}")
                        break
            p.write_text(newtext, encoding="utf-8")
            if newpath != p:
                p.rename(newpath)

        # Move files into module folders
        src.mkdir(exist_ok=True, parents=True)
        for name, addr, summary in funcs:
            mod = mod_map.get(name, "misc")
            moddir = src / mod
            moddir.mkdir(exist_ok=True)
            # find file by either original or suggested base
            candidates = list(src.glob(f"func_*{sanitize_ident(name)}*.c")) + list(src.glob(f"func_*{sanitize_ident(suggest_name(name, summary))}*.c"))
            for f in candidates:
                try:
                    f.rename(moddir / f.name)
                except Exception:
                    pass

    # Generate overview.md
    docs = outdir / "docs"
    docs.mkdir(exist_ok=True)
    with open(docs / "overview.md", "w", encoding="utf-8") as w:
        w.write("# Project Overview\n\n")
        w.write("This document was generated by humanize_project.py.\n\n")
        w.write("## Functions\n\n")
        w.write("| Function | Suggested | Address | Module |\n|---|---|---|---|\n")
        for s in uniq:
            mod = mod_map.get(s["original"], "misc")
            w.write(f"| `{s['original']}` | `{s['suggested']}` | {s['address']} | {mod} |\n")

    # Call graph from out.json callers if provided
    callers, callees = ({},{})
    if args.outjson:
        callers, callees = load_out_json_callers(pathlib.Path(args.outjson))

    with open(docs / "callgraph.dot", "w", encoding="utf-8") as w:
        w.write("digraph callgraph {\n  rankdir=LR;\n  node [shape=box, fontsize=10];\n")
        def short(n): return n.replace('"','')
        nodes = set(list(callers.keys()) + list(callees.keys()))
        for n in nodes:
            w.write(f'  "{short(n)}";\n')
        for callee, cs in callers.items():
            for c in cs:
                w.write(f'  "{short(c)}" -> "{short(callee)}";\n')
        w.write("}\n")

    # Format files: emit .clang-format and Doxygen starter
    clang = outdir / ".clang-format"
    if not clang.exists():
        clang.write_text(textwrap.dedent("""\
        BasedOnStyle: LLVM
        IndentWidth: 4
        ColumnLimit: 100
        ReflowComments: false
        """).strip()+"\n", encoding="utf-8")

    doxy = outdir / "Doxyfile.sample"
    if not doxy.exists():
        doxy.write_text(textwrap.dedent("""\
        PROJECT_NAME = "Recovered Project"
        RECURSIVE = YES
        INPUT = ./include ./src
        GENERATE_HTML = YES
        EXTRACT_ALL = YES
        QUIET = YES
        """).strip()+"\n", encoding="utf-8")

    print(f"[✓] Suggestions written to: {names_yaml}")
    print(f"[✓] Modules map written to: {modules_yaml}")
    print(f"[✓] Humanized project at:  {outdir}")
    print(f"[✓] Docs: {docs/'overview.md'}, {docs/'callgraph.dot'}")
    if not args.apply:
        print("\nNext: review NAME_SUGGESTIONS.yaml, then re-run with --apply to perform renames/moves.")
    else:
        print("\nRenames & moves applied. Consider running clang-format on src/ and include/.")

if __name__ == "__main__":
    # lazy dependency: PyYAML
    try:
        import yaml  # noqa
    except Exception:
        print("[!] This script requires PyYAML: pip install pyyaml", flush=True)
        raise
    main()

