#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_autodiscover.py — discover target_out + binary in work/, enrich, LLM label, write mapping/report.

Updates:
- Smarter target_out discovery: env(HUNT_TARGET_OUT) → work/*.json → work/snapshots/*.json → recursive work/**/_out.json
- Fallback if missing: synthesize functions from work/recovered_project/src (regex parse of defs; snippets)
- Heartbeat + timed FLOSS/CAPA/YARA stages (unchanged)
"""

from __future__ import annotations
import os, sys, json, time, glob, shutil, threading, subprocess, re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---- imports
try:
    from .label import llm_label_batch
except Exception:
    sys.path.append(str(Path(__file__).resolve().parent))
    from label import llm_label_batch  # type: ignore

# ---- env / defaults
WORK_DIR       = Path(os.getenv("WORK_DIR", "work"))
OUT_DIR        = WORK_DIR / "hunt"; OUT_DIR.mkdir(parents=True, exist_ok=True)
MAPPING_PATH   = OUT_DIR / "functions.labeled.jsonl"
REPORT_PATH    = OUT_DIR / "report.md"

HUNT_TOPN      = int(os.getenv("HUNT_TOPN", "1000") or 0)
HUNT_MIN_SIZE  = int(os.getenv("HUNT_MIN_SIZE", "0") or 0)

ENABLE_FLOSS   = os.getenv("ENABLE_FLOSS", "1").lower() in ("1","true","yes","on")
ENABLE_CAPA    = os.getenv("ENABLE_CAPA",  "1").lower() in ("1","true","yes","on")
ENABLE_YARA    = os.getenv("ENABLE_YARA",  "1").lower() in ("1","true","yes","on")

FLOSS_ARGS     = os.getenv("FLOSS_ARGS", "")
FLOSS_MINLEN   = os.getenv("FLOSS_MINLEN", "")
FLOSS_PER_FN   = int(os.getenv("FLOSS_PER_FN", "20") or 20)

CAPA_TIMEOUT   = int(os.getenv("HUNT_CAPA_TIMEOUT", "180") or 180)
FLOSS_TIMEOUT  = int(os.getenv("HUNT_FLOSS_TIMEOUT", "600") or 600)
YARA_TIMEOUT   = int(os.getenv("HUNT_YARA_TIMEOUT", "90") or 90)

LLM_ENDPOINT   = os.getenv("LLM_ENDPOINT")
LLM_MODEL      = os.getenv("LLM_MODEL")

SRC_TREE       = WORK_DIR / "recovered_project" / "src"   # for synth fallback

# ---- logging
def ts() -> str: return time.strftime("%Y-%m-%d %H:%M:%S")
def log(msg: str) -> None: print(msg, flush=True)
def stage_start(name: str) -> float:
    t0 = time.time(); log(f"[hunt] >>> {name}…  ({ts()})"); return t0
def stage_done(name: str, t0: float, extra: str="") -> None:
    dt = time.time()-t0; log(f"[hunt] <<< {name} done in {dt:.1f}s{('  '+extra) if extra else ''}")

# ---- heartbeat
_hb_stop = threading.Event()
def _heartbeat(msg="[hunt] heartbeat… still analyzing", period=30):
    while not _hb_stop.is_set():
        time.sleep(period)
        if not _hb_stop.is_set(): log(msg)
def start_heartbeat():
    _hb_stop.clear()
    t = threading.Thread(target=_heartbeat, daemon=True); t.start(); return t
def stop_heartbeat(): _hb_stop.set()

# ---- helpers
def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            d = fh.read(0x100)
        if d[:2] != b"MZ": return False
        if len(d) < 0x40: return False
        e = int.from_bytes(d[0x3C:0x40], "little")
        return 0 < e < 100_000_000
    except Exception:
        return False

def discover_binary(work_root: Path) -> Optional[Path]:
    env_bin = os.getenv("HUNT_BIN")
    if env_bin and Path(env_bin).is_file(): return Path(env_bin)
    if (work_root / "primary_bin.txt").is_file():
        cand = Path((work_root / "primary_bin.txt").read_text().strip())
        if cand.is_file(): return cand
    best: Tuple[int, Optional[Path]] = (0, None)
    for p in work_root.iterdir():
        if not p.is_file(): continue
        n = p.name.lower()
        if not (n.endswith(".exe") or n.endswith(".dll") or n.endswith(".bin")): continue
        if _is_pe(p):
            sz = 0
            try: sz = p.stat().st_size
            except Exception: pass
            if sz > best[0]: best = (sz, p)
    return best[1]

def _newest(paths: List[Path]) -> Optional[Path]:
    if not paths: return None
    try: paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception: return paths[0]
    return paths[0]

def discover_target_out(work_root: Path) -> Optional[Path]:
    # 1) explicit env
    envp = os.getenv("HUNT_TARGET_OUT")
    if envp and Path(envp).is_file(): return Path(envp)

    # 2) root: *_out.json
    root = _newest(list(work_root.glob("*_out.json")))
    if root: return root

    # 3) common subdir: snapshots/
    snap = _newest(list((work_root / "snapshots").glob("*_out.json")))
    if snap: return snap

    # 4) last resort: shallow recursive search (depth <= 2)
    cands: List[Path] = []
    for sub in [work_root, work_root / "extracted", work_root / "snapshots"]:
        try:
            cands.extend(sub.rglob("*_out.json"))
        except Exception:
            pass
    return _newest(cands)

# ---- load functions from JSON
def _safe_len(s: str) -> int: return len(s.encode("utf-8", errors="ignore"))

def load_functions_from_target_out(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    funcs: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for key in ("functions","items"):
            if isinstance(data.get(key), list): funcs = data[key]; break
        if not funcs:
            for v in data.values():
                if isinstance(v, list) and v and isinstance(v[0], dict) and ("name" in v[0] or "address" in v[0]):
                    funcs = v; break
    elif isinstance(data, list):
        funcs = data

    norm: List[Dict[str, Any]] = []
    for f in funcs:
        if not isinstance(f, dict): continue
        name = str(f.get("name") or f.get("func_name") or f.get("symbol") or "sub_unknown")
        addr = f.get("address") or f.get("addr") or f.get("ea")
        if isinstance(addr, str) and addr.lower().startswith("0x"):
            try: addr = int(addr, 16)
            except Exception: addr = None
        elif isinstance(addr, (int, float)):
            addr = int(addr)
        else:
            addr = None
        snippet = str(f.get("decompiled") or f.get("pseudocode") or f.get("snippet") or f.get("code") or "")
        size = int(f.get("size") or 0)
        if size <= 0: size = max(_safe_len(snippet), 1)
        norm.append({
            "name": name, "addr": addr, "snippet": snippet, "size": size,
            "imports": f.get("imports") or [], "strings": f.get("strings") or [],
            "callers": f.get("callers") or [], "callees": f.get("callees") or [],
            "module": f.get("module") or f.get("file") or None,
        })
    return norm

# ---- synthesize from source (fallback)
_kw = {"if","for","while","switch","return","sizeof"}
def _find_functions_in_c(text: str) -> List[Tuple[str, str]]:
    """Return [(name, body_snippet)] naive but robust enough for sub_* funcs."""
    out: List[Tuple[str,str]] = []
    # find lines that look like 'ret type ... name(args) {' and then capture the {...} block
    sig_iter = re.finditer(r'^[ \t]*[A-Za-z_][\w \t\*]*\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{', text, re.MULTILINE)
    for m in sig_iter:
        name = m.group(1)
        if name in _kw: continue
        # brace matching from m.end()-1
        i = m.end()-1; depth = 0; j = i
        for k in range(i, len(text)):
            ch = text[k]
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0: j = k+1; break
        body = text[m.start():j] if j > i else text[m.start():min(len(text), m.start()+4000)]
        out.append((name, body))
    return out

def synthesize_functions_from_source(src_root: Path, topn: int = 1000) -> List[Dict[str, Any]]:
    files = sorted(src_root.rglob("*.c"))
    recs: List[Dict[str, Any]] = []
    for p in files:
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for name, body in _find_functions_in_c(t):
            # Prefer sub_* names; skip obvious non-targets if exploding
            if not (name.startswith("sub_") or name.startswith("FUN_")):
                continue
            sz = _safe_len(body)
            recs.append({"name": name, "addr": None, "snippet": body[:8000], "size": sz,
                         "imports": [], "strings": [], "callers": [], "callees": [],
                         "module": str(p.relative_to(src_root))})
    # rank by size desc and cut
    recs.sort(key=lambda r: int(r.get("size") or 0), reverse=True)
    if topn and len(recs) > topn: recs = recs[:topn]
    return recs

# ---- enrich (timed)
def has_tool(name: str) -> bool: return shutil.which(name) is not None
def _run(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False, text=True)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -999, "", f"timeout after {timeout}s"

def enrich(funcs: List[Dict[str, Any]], bin_path: Path) -> None:
    t0_all = stage_start("enrich()")

    # FLOSS
    t0 = stage_start("FLOSS")
    if ENABLE_FLOSS and has_tool("floss"):
        args = ["floss", "-q", "-j"]
        if FLOSS_MINLEN: args += ["--min-length", str(FLOSS_MINLEN)]
        if FLOSS_ARGS:   args += FLOSS_ARGS.split()
        args.append(str(bin_path))
        rc, out, err = _run(args, FLOSS_TIMEOUT)
        hits = 0
        if rc == 0 and out:
            try:
                j = json.loads(out)
                strings = []
                for sec in ("stack_strings","decoded_strings","static_strings"):
                    for srec in (j.get(sec) or [])[:FLOSS_PER_FN]:
                        s = srec.get("string") if isinstance(srec, dict) else srec
                        if isinstance(s, str): strings.append(s[:120])
                for f in funcs:
                    f.setdefault("strings", [])
                    f["strings"] = (f["strings"] or []) + strings[:FLOSS_PER_FN]
                hits = len(strings)
            except Exception as e:
                log(f"[floss] warn: failed to parse output: {e}")
        else:
            log(f"[floss] skipped rc={rc} err={err.strip()[:200]}")
        stage_done("FLOSS", t0, f"(strings≈{hits})")
    else:
        stage_done("FLOSS", t0, "(disabled or tool missing)")

    # CAPA
    t0 = stage_start("CAPA")
    capa_hits = 0
    if ENABLE_CAPA and has_tool("capa"):
        rc, out, err = _run(["capa","-q","-j", str(bin_path)], CAPA_TIMEOUT)
        if rc == 0 and out:
            try:
                rules = (json.loads(out).get("rules") or {})
                capa_hits = len(rules)
                for f in funcs:
                    f.setdefault("capa_summary", {"rules": capa_hits})
            except Exception as e:
                log(f"[capa] warn: parse error: {e}")
        else:
            log(f"[capa] skipped rc={rc} err={err.strip()[:200]}")
        stage_done("CAPA", t0, f"(rules≈{capa_hits})")
    else:
        stage_done("CAPA", t0, "(disabled or tool missing)")

    # YARA
    t0 = stage_start("YARA")
    yara_hits = 0
    if ENABLE_YARA and has_tool("yara"):
        rules_dir = os.getenv("YARA_RULES_DIR", "")
        if not rules_dir:
            repo_rules = Path("tools/yara")
            if repo_rules.is_dir(): rules_dir = str(repo_rules)
        if rules_dir and Path(rules_dir).exists():
            rc, out, err = _run(["yara","-r", rules_dir, str(bin_path)], YARA_TIMEOUT)
            if rc in (0,1) and out:
                yara_hits = len([ln for ln in out.splitlines() if ln.strip()])
                for f in funcs: f.setdefault("yara_hits", yara_hits)
            else:
                log(f"[yara] no matches or error rc={rc} err={err.strip()[:200]}")
            stage_done("YARA", t0, f"(hits≈{yara_hits})")
        else:
            stage_done("YARA", t0, "(no rules directory)")
    else:
        stage_done("YARA", t0, "(disabled or tool missing)")

    stage_done("enrich()", t0_all)

# ---- report
def write_report(path: Path, funcs: List[Dict[str, Any]], labeled: Optional[List[Dict[str, Any]]]=None) -> None:
    lines = [ "# Function Hunt Report",
              f"- Generated: {ts()}",
              f"- Functions considered: {len(funcs)}" ]
    if labeled is not None:
        named = sum(1 for r in labeled if r and r.get("name"))
        lines.append(f"- Labeled by LLM: {named}/{len(labeled)}")
    lines.append(""); lines.append("| addr | original | label | confidence |")
    lines.append("|---:|---|---|---:|")
    for i, f in enumerate(funcs[:2000]):
        orig = f.get("name","sub_unknown")
        addr = f.get("addr"); addr_s = f"0x{addr:X}" if isinstance(addr,int) else "-"
        lab, conf = "", ""
        if labeled and i < len(labeled) and labeled[i]:
            lab = labeled[i].get("name") or ""
            conf = f"{labeled[i].get('confidence','')}"
        lines.append(f"| {addr_s} | {orig} | {lab} | {conf} |")
    path.write_text("\n".join(lines), encoding="utf-8")
    log(f"[hunt] wrote {path}  (functions: {len(funcs)})")

# ---- main
def main() -> int:
    log(f"[hunt] work dir: {WORK_DIR}")
    log("[hunt] starting discover…")

    bin_path = discover_binary(WORK_DIR)
    tgt_out  = discover_target_out(WORK_DIR)

    if not bin_path or not bin_path.exists():
        log(f"[hunt] ERROR: binary not found at {WORK_DIR} root. Set HUNT_BIN or place *.exe|*.dll|*.bin in work/")
        return 2

    funcs: List[Dict[str, Any]] = []
    if tgt_out and tgt_out.exists():
        log(f"[hunt] binary     : {bin_path}")
        log(f"[hunt] target_out : {tgt_out}")
        log(f"[hunt] out dir    : {OUT_DIR}")
        hb = start_heartbeat()
        try:
            funcs = load_functions_from_target_out(tgt_out)
            log(f"[hunt] discovered: {len(funcs)}")
        finally:
            pass
    else:
        # Fallback — synthesize from source tree
        log("[hunt] WARN: no *_out.json found → synthesizing functions from source tree…")
        log(f"[hunt] src tree   : {SRC_TREE}")
        if not SRC_TREE.is_dir():
            log(f"[hunt] ERROR: missing both *_out.json and source tree ({SRC_TREE}).")
            return 2
        hb = start_heartbeat()
        try:
            funcs = synthesize_functions_from_source(SRC_TREE, topn=HUNT_TOPN or 1000)
            log(f"[hunt] synthesized: {len(funcs)} (from source)")
        finally:
            pass

    # filter/sort/topn
    if HUNT_MIN_SIZE > 0:
        before = len(funcs)
        funcs = [f for f in funcs if int(f.get("size") or 0) >= HUNT_MIN_SIZE]
        log(f"[hunt] filtered by HUNT_MIN_SIZE={HUNT_MIN_SIZE}: {before} → {len(funcs)}")
    funcs.sort(key=lambda f: int(f.get("size") or 0), reverse=True)
    if HUNT_TOPN > 0 and len(funcs) > HUNT_TOPN:
        log(f"[hunt] taking top {HUNT_TOPN} by size (HUNT_TOPN) → {HUNT_TOPN}")
        funcs = funcs[:HUNT_TOPN]
    log(f"[hunt] functions normalized: {len(funcs)}")

    # enrich (bin required even for synth mode)
    enrich(funcs, bin_path)
    stop_heartbeat()

    # LLM label
    t0_llm = stage_start("llm_label_batch()")
    labeled = llm_label_batch(funcs, LLM_ENDPOINT, LLM_MODEL)
    stage_done("llm_label_batch()", t0_llm)

    # mapping
    with MAPPING_PATH.open("w", encoding="utf-8") as fh:
        for f, lab in zip(funcs, labeled):
            fh.write(json.dumps({
                "_orig_name": f.get("name"),
                "addr": f.get("addr"),
                "name": (lab or {}).get("name") or f.get("name"),
                "confidence": (lab or {}).get("confidence"),
                "tags": (lab or {}).get("tags"),
                "inputs": (lab or {}).get("inputs"),
                "outputs": (lab or {}).get("outputs"),
                "side_effects": (lab or {}).get("side_effects"),
                "evidence": (lab or {}).get("evidence"),
            }, ensure_ascii=False) + "\n")

    # report
    log("[hunt] writing report…")
    write_report(REPORT_PATH, funcs, labeled)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("[hunt] interrupted by user"); sys.exit(130)

