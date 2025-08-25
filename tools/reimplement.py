#!/usr/bin/env python3
"""
tools/reimplement.py

Re-implementation Stage Enhancements:
- AST-safe body replacement with pycparser (preserves signature & qualifiers).
- Guard rails: auto-insert asserts / bounds checks when inputs suggest sizes.
- Unit scaffold: emit tiny tests for high-confidence functions into tests/.
- Linkage awareness: if evidence/tags hint WinAPI/FM0D/etc., add compile notes and optional shim includes.
- Change log: write per-function *.patch.md with name, confidence, rationale.

Inputs:
  --src-dir <dir>         Source tree to modify (e.g., work/recovered_project/src)
  --mapping <file>        functions.labeled.jsonl from Function Hunt
  --out-dir <dir>         Output source dir for reimplemented files (default work/recovered_project_reimpl/src)
  --tests-dir <dir>       Output tests dir (default work/reimplement/tests)
  --threshold <float>     Confidence threshold to re-implement (default 0.78)
  --max-fns <int>         Max functions to attempt (default 120)
  --dry-run               Do not write files; just print summary
  --llm-endpoint <url>    Optional LLM for codegen (statements only)
  --model <name>          LLM model id
  --max-tokens <int>      LLM max tokens (default 768)

Env used:
  HUMANIZE_AST=1            (already from your humanize bootstrap)
  REIMPL_INCLUDE_SHIMS=1    include tools/reimpl_shims.h in tests (default on)
"""
from __future__ import annotations
import os, re, json, argparse, textwrap, hashlib, time
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

# Third-party
import requests
from pycparser import c_parser, c_ast, c_generator

# ---------- CLI ----------
def parse_args():
    ap = argparse.ArgumentParser(description="AST-safe reimplementation stage")
    ap.add_argument("--src-dir", required=True)
    ap.add_argument("--mapping", required=True)
    ap.add_argument("--out-dir", default="work/recovered_project_reimpl/src")
    ap.add_argument("--tests-dir", default="work/reimplement/tests")
    # Support both --threshold and legacy --min-conf; env fallback supports
    # REIMPL_THRESHOLD or legacy REIMPL_MIN_CONF.
    default_thr = float(os.getenv("REIMPL_THRESHOLD", os.getenv("REIMPL_MIN_CONF","0.78")))
    ap.add_argument("--threshold", type=float, default=default_thr)
    ap.add_argument("--min-conf", dest="threshold", type=float, help="alias of --threshold")
    ap.add_argument("--max-fns", type=int, default=int(os.getenv("REIMPL_MAX_FNS","120")))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--llm-endpoint", default=os.getenv("LLM_ENDPOINT",""))
    ap.add_argument("--model", default=os.getenv("LLM_MODEL",""))
    ap.add_argument("--max-tokens", type=int, default=int(os.getenv("REIMPL_MAX_TOKENS","768")))
    return ap.parse_args()

# ---------- IO helpers ----------
def load_mapping(path: Path) -> List[Dict[str,Any]]:
    out = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln: continue
            try:
                j = json.loads(ln)
                out.append(j)
            except Exception:
                pass
    return out

def walk_c_files(src_dir: Path) -> List[Path]:
    return [p for p in src_dir.rglob("*.c") if p.is_file()]

# ---------- Evidence utilities ----------
def want_windows_includes(rec: Dict[str,Any]) -> bool:
    tags = [str(t).lower() for t in (rec.get("tags") or [])]
    evs  = [str(e).lower() for e in (rec.get("evidence") or [])]
    # quick heuristics
    needles = [
        "createfile", "regopenkey", "wininet", "ws2_32", "advapi32",
        "kernel32", "user32", "shell32", "winsock", "winhttp",
        "fmod", "fmod_", "directsound", "mmdevice"
    ]
    blob = " ".join(tags + evs)
    return any(n in blob for n in needles)

def inputs_outputs(rec: Dict[str,Any]) -> Tuple[List[str], List[str]]:
    inp = [str(x) for x in (rec.get("inputs") or [])]
    out = [str(x) for x in (rec.get("outputs") or [])]
    return (inp, out)

# ---------- LLM ----------
def call_llm(endpoint: str, model: str, prompt: str, max_tokens: int=768, retries: int=2) -> str:
    if not endpoint or not model:
        return ""
    payload = {
        "model": model,
        "messages": [
            {"role":"system","content":"Return only valid C statements for the body (no function signature). Avoid undefined behavior. Check return codes. Use clear names. No comments unless they clarify intent."},
            {"role":"user","content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": max_tokens
    }
    use_json = os.getenv("REIMPL_JSON_MODE","0") in ("1","true","on","yes")
    if use_json:
        payload["response_format"] = {"type":"text"}  # we want raw C statements

    last_err = None
    for _ in range(retries+1):
        try:
            r = requests.post(endpoint, json=payload, timeout=90)
            if not r.ok:
                # fallback: drop response_format if server complains
                if r.status_code in (400,422) and "response_format" in (r.text or "").lower():
                    payload.pop("response_format", None)
                    continue
                r.raise_for_status()
            data = r.json()
            ch = (data.get("choices") or [{}])[0]
            msg = ch.get("message") or {}
            txt = (msg.get("content") or msg.get("reasoning_content") or ch.get("text") or "").strip()
            return txt
        except Exception as e:
            last_err = e
            time.sleep(0.6)
    return f"/* TODO: AI codegen unavailable: {str(last_err)[:120]} */"

# ---------- AST helpers ----------
_GEN = c_generator.CGenerator()
_PARSER = c_parser.CParser()

def _parse_unit(code: str) -> c_ast.FileAST:
    # pycparser operates best without real system headers;
    # sources from Ghidra dumps usually don't include system headers anyway.
    return _PARSER.parse(code, filename="<mem>")

def _find_funcdefs(ast: c_ast.Node) -> List[c_ast.FuncDef]:
    found: List[c_ast.FuncDef] = []
    class V(c_ast.NodeVisitor):
        def visit_FuncDef(self, node):  # type: ignore
            found.append(node)
    V().visit(ast)
    return found

def _ret_default_for(decl: c_ast.Decl) -> str:
    # crude return type inference from declaration
    t = decl.type
    # peel layers
    while hasattr(t, "type"):
        t = t.type
    tname = getattr(t, "names", ["int"])
    base = " ".join(tname) if isinstance(tname, list) else str(tname)
    base = base.lower()
    if "void" in base: return "/*guard*/ return;"
    if "bool" in base: return "/*guard*/ return false;"
    if any(x in base for x in ("float","double")): return "/*guard*/ return 0.0;"
    if any(x in base for x in ("char","short","long","int","size_t","ssize_t","ptrdiff_t","uint","int8","int16","int32","int64","uint8","uint16","uint32","uint64")):
        return "/*guard*/ return 0;"
    # pointer? often encoded as PtrDecl above; fall through
    return "/*guard*/ return 0;"

def _guard_snippets(func: c_ast.FuncDef) -> str:
    # build minimal guards based on parameter names
    decl = func.decl
    params: List[Tuple[str,str]] = []  # (name, typename string-ish)
    try:
        plist = decl.type.args.params if decl.type and decl.type.args else []
        for p in plist:
            if isinstance(p, c_ast.Decl):
                pname = p.name or ""
                ptype = _GEN.visit(p.type) if hasattr(p, "type") else ""
                params.append((pname, ptype))
    except Exception:
        pass

    # heuristics
    buf_names  = {"buf","dst","src","data","out","in","buffer","ptr","bytes","payload"}
    size_names = {"len","size","count","capacity","n","nbytes","length"}

    buf_vars  = [n for n,_ in params if n and any(b in n.lower() for b in buf_names)]
    size_vars = [n for n,_ in params if n and any(s == n.lower() for s in size_names)]

    guards: List[str] = []
    for b in buf_vars:
        guards.append(f"if (!{b}) {{ {_ret_default_for(decl)} }}")
    for s in size_vars:
        guards.append(f"if ({s} <= 0) {{ {_ret_default_for(decl)} }}")

    # dedupe & join
    guards = list(dict.fromkeys(guards))
    return "\n    ".join(guards)

def _make_body_compound(body_code: str) -> c_ast.Compound:
    # Wrap as a dummy function to parse statements cleanly
    stub = "void __dummy(void) {\n" + body_code + "\n}\n"
    try:
        ast = _parse_unit(stub)
        fns = _find_funcdefs(ast)
        if not fns:
            raise ValueError("no func in stub")
        return fns[0].body
    except Exception:
        # Fallback to an empty compound
        return c_ast.Compound([])

def _replace_body(func: c_ast.FuncDef, new_body_code: str) -> None:
    func.body = _make_body_compound(new_body_code)

def _rewrite_file(in_path: Path, out_path: Path, replacements: Dict[str, Dict[str,Any]]) -> Tuple[int,int]:
    """
    replacements: name -> {
        'body_code': str,
        'changelog': str or list[str]
    }
    Returns (#replaced, #total-candidates-in-file)
    """
    code = in_path.read_text(encoding="utf-8", errors="ignore")
    try:
        ast = _parse_unit(code)
    except Exception as e:
        # fallback textual replacement (only as last resort)
        replaced = 0
        for fname, spec in replacements.items():
            pattern = rf"(\b{re.escape(fname)}\b\s*\([^)]*\)\s*\{{)(.*?)(\n\}})"
            new_body = "\n{\n" + textwrap.indent(spec["body_code"], "    ") + "\n}\n"
            new_code, n = re.subn(pattern, r"\1\n" + textwrap.indent(spec["body_code"], "    ") + r"\3", code, flags=re.S)
            if n:
                code = new_code
                replaced += 1
        if replaced:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(code, encoding="utf-8")
        return replaced, len(replacements)

    # AST path
    funcdefs = _find_funcdefs(ast)
    to_apply = {k:v for k,v in replacements.items()}
    replaced = 0
    for fn in funcdefs:
        name = fn.decl.name if fn and fn.decl else None
        if name and name in to_apply:
            _replace_body(fn, to_apply[name]["body_code"])
            replaced += 1

    if replaced:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_code = _GEN.visit(ast)
        out_path.write_text(out_code, encoding="utf-8")
    return replaced, len(replacements)

# ---------- Test scaffolding ----------
TEST_HEADER = """\
/* Auto-generated minimal unit scaffold.
 * Fill in concrete inputs/expected values before running.
 */
#include <stdio.h>
#include <assert.h>
{win_inc}
{shim_inc}
int main(void) {{
    /* TODO: Provide realistic arguments & expected results */
{calls}
    printf("[ok] basic scaffolds executed.\\n");
    return 0;
}}
"""

def emit_test_scaffold(tests_dir: Path, fname: str, call_lines: List[str], want_win: bool) -> Path:
    tests_dir.mkdir(parents=True, exist_ok=True)
    win_inc  = "#include <windows.h>" if want_win else ""
    shim_inc = '#include "../tools/reimpl_shims.h"' if (os.getenv("REIMPL_INCLUDE_SHIMS","1") in ("1","true","yes","on")) else ""
    body = TEST_HEADER.format(
        win_inc=win_inc, shim_inc=shim_inc, calls="\n".join("    "+l for l in call_lines)
    )
    out = tests_dir / f"test_{fname}.c"
    out.write_text(body, encoding="utf-8")
    return out

# ---------- Changelog ----------
def emit_patch_md(base_dir: Path, rec: Dict[str,Any], src_file: Path, replaced: bool, reason: str, code_hash: str) -> None:
    patches = base_dir / "patches"
    patches.mkdir(parents=True, exist_ok=True)
    name = rec.get("name","unknown")
    addr = rec.get("_addr","")
    path = patches / f"{name}_{addr}.patch.md"
    ev  = rec.get("evidence") or []
    md = []
    md.append(f"# Re-implementation Patch — `{name}` @ {addr}")
    md.append("")
    md.append(f"- Source file: `{src_file}`")
    md.append(f"- Confidence: **{rec.get('confidence',0):.2f}**")
    md.append(f"- Replaced: **{replaced}**")
    md.append(f"- Reason: {reason}")
    md.append(f"- Body hash: `{code_hash}`")
    if ev:
        md.append("\n## Rationale / Evidence (subset)\n")
        for e in ev[:12]:
            md.append(f"- {str(e)[:240]}")
    Path(path).write_text("\n".join(md)+"\n", encoding="utf-8")

# ---------- Re-impl body synthesis ----------
def synth_body_for(rec: Dict[str,Any], fn: c_ast.FuncDef, opts: Dict[str,Any]) -> Tuple[str, str]:
    """
    Returns: (final_body_code, reason_string)
    """
    # Guard rails
    guards = _guard_snippets(fn)
    guard_block = (guards + "\n") if guards else ""

    # LLM prompt (statements only)
    llm_txt = ""
    if opts["endpoint"] and opts["model"]:
        # High-signal evidence summary:
        sig = rec.get("signals") or {}
        prompt = textwrap.dedent(f"""
        Implement the function body (C statements only) given:
        - function: {fn.decl.name}
        - return type: {_GEN.visit(fn.decl.type.type) if hasattr(fn.decl.type,'type') else 'unknown'}
        - params: {_GEN.visit(fn.decl.type.args) if hasattr(fn.decl.type,'args') and fn.decl.type.args else '()'}
        - inputs: {rec.get('inputs',[])}
        - outputs: {rec.get('outputs',[])}
        - tags: {rec.get('tags',[])}
        - IAT (by DLL): {sig.get('iat_by_dll')}
        - decoded strings: {(sig.get('floss_strings') or [])[:12]}
        - string xrefs: {(sig.get('string_xrefs') or [])[:8]}
        - callers: {(sig.get('callers') or [])[:6]}
        - callees: {(sig.get('callees') or [])[:6]}

        Constraints:
        - Do not change the function signature.
        - Avoid undefined behavior; check bounds/sizes; check API return codes.
        - Use idiomatic C and clear variable names; no magic constants (use named locals).
        - Prefer defensive returns if invalid inputs.

        Output:
        - ONLY C statements to place inside the function body.
        """).strip()
        llm_txt = call_llm(opts["endpoint"], opts["model"], prompt, opts["max_tokens"])

    # Final body
    body = ""
    if guard_block or llm_txt:
        body = textwrap.indent(guard_block + (f"/* BEGIN AI REIMPL */\n{llm_txt}\n/* END AI REIMPL */" if llm_txt else ""), "    ")
    else:
        body = "    /* TODO: No AI / guards only */\n"
    return body, ("ai+guards" if llm_txt else "guards_only")

# ---------- Main ----------
def main():
    args = parse_args()
    src_dir   = Path(args.src_dir)
    mapping   = Path(args.mapping)
    out_src   = Path(args.out_dir)
    tests_dir = Path(args.tests_dir)

    out_root  = out_src.parent.parent if out_src.name == "src" else out_src.parent
    patches_root = out_root / "reimplement"

    print("==============================================")
    print(" Re-implementation Stage")
    print(f" src      : {src_dir}")
    print(f" mapping  : {mapping}")
    print(f" out src  : {out_src}")
    print(f" tests    : {tests_dir}")
    print(f" threshold: {args.threshold}  max_fns: {args.max_fns}")
    print(f" LLM      : {args.model or '<none>'} @ {args.llm_endpoint or '<none>'}")
    print("==============================================")

    recs = load_mapping(mapping)
    # Prefer high-confidence first
    recs = sorted(recs, key=lambda r: float(r.get("confidence",0.0)), reverse=True)
    recs = [r for r in recs if float(r.get("confidence",0.0)) >= args.threshold]
    if args.max_fns and len(recs) > args.max_fns:
        recs = recs[:args.max_fns]

    # index functions by name across all source files
    c_files = walk_c_files(src_dir)
    name_to_files: Dict[str,List[Path]] = {}
    for p in c_files:
        try:
            code = p.read_text(encoding="utf-8", errors="ignore")
            # simple name scan to pre-filter
            found = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))
            for nm in found:
                name_to_files.setdefault(nm, []).append(p)
        except Exception:
            pass

    opts = {
        "endpoint": args.llm_endpoint,
        "model": args.model,
        "max_tokens": args.max_tokens,
    }

    # process
    total = len(recs)
    done  = 0
    start_ts = time.time()
    out_src.mkdir(parents=True, exist_ok=True)
    (patches_root / "patches").mkdir(parents=True, exist_ok=True)

    for rec in recs:
        fname = rec.get("name") or rec.get("_orig_name") or ""
        if not fname:
            continue
        cand_files = name_to_files.get(fname, [])
        if not cand_files:
            # try original name if available
            on = rec.get("_orig_name")
            if on and on != fname:
                cand_files = name_to_files.get(on, [])
        if not cand_files:
            # give up on this one
            done += 1
            continue

        for cpath in cand_files:
            code = cpath.read_text(encoding="utf-8", errors="ignore")
            try:
                ast = _parse_unit(code)
            except Exception:
                continue
            funcdefs = _find_funcdefs(ast)
            target_fn = None
            for fn in funcdefs:
                if fn.decl and fn.decl.name == fname:
                    target_fn = fn; break
            if not target_fn:
                continue

            body_code, reason = synth_body_for(rec, target_fn, opts)
            code_hash = hashlib.sha1(body_code.encode("utf-8","ignore")).hexdigest()[:12]

            # apply to file AST
            _replace_body(target_fn, body_code)
            out_file = out_src / cpath.relative_to(src_dir)
            if not args.dry_run:
                out_file.parent.mkdir(parents=True, exist_ok=True)
                out_code = _GEN.visit(ast)
                out_file.write_text(out_code, encoding="utf-8")
                emit_patch_md(patches_root, rec, cpath, True, reason, code_hash)

            # test scaffold (only for very high confidence)
            if float(rec.get("confidence",0.0)) >= max(args.threshold+0.1, 0.88):
                want_win = want_windows_includes(rec)
                # create a trivial call line with zeros/NULLs based on param count
                params = []
                try:
                    plist = target_fn.decl.type.args.params if target_fn.decl.type.args else []
                except Exception:
                    plist = []
                n = len(plist) if plist else 0
                args_list = ", ".join(["0"]*n) if n else ""
                call_lines = [f"(void){fname}({args_list}); /* TODO: set meaningful args & asserts */"]
                if not args.dry_run:
                    emit_test_scaffold(Path(tests_dir), fname, call_lines, want_win)

            break  # first matching file is enough

        done += 1
        # progress/ETA
        if done == total or done % max(5, total//20 or 1) == 0:
            elapsed = time.time() - start_ts
            rate = done/elapsed if elapsed>0 else 0.0
            remain = int((total-done)/rate) if rate>0 else -1
            eta = time.strftime("%H:%M:%S", time.gmtime(remain)) if remain>=0 else "??:??:??"
            print(f"[reimpl] progress {done}/{total} | {int(100*done/total)}% | elapsed {int(elapsed)}s | ETA {eta}")

    print(f"[reimpl] done. processed={done}/{total}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

