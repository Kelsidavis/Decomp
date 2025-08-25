#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_autodiscover.py — discover target_out + binary in work/, enrich, LLM label, write mapping/report.

Adds:
- Heartbeat while analyzing/enriching
- Stage timing for enrich sub-stages (FLOSS / CAPA / YARA) with clear start/stop lines
- Chattier logs throughout; explicit discover/enrich boundaries
"""

from __future__ import annotations
import os
import sys
import json
import time
import glob
import shutil
import threading
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Local imports
# label.py is expected to live next to this script (tools/function_hunt/label.py)
try:
    from .label import llm_label_batch
except Exception:
    # fallback if run as a script without a package context
    sys.path.append(str(Path(__file__).resolve().parent))
    from label import llm_label_batch  # type: ignore

# ------------ Environment / defaults ------------
WORK_DIR = Path(os.getenv("WORK_DIR", "work"))
HUNT_TOPN = int(os.getenv("HUNT_TOPN", "1000") or 0)
HUNT_MIN_SIZE = int(os.getenv("HUNT_MIN_SIZE", "0") or 0)

ENABLE_FLOSS = os.getenv("ENABLE_FLOSS", "1").lower() in ("1", "true", "yes", "on")
ENABLE_CAPA  = os.getenv("ENABLE_CAPA",  "1").lower() in ("1", "true", "yes", "on")
ENABLE_YARA  = os.getenv("ENABLE_YARA",  "1").lower() in ("1", "true", "yes", "on")

FLOSS_ARGS   = os.getenv("FLOSS_ARGS", "")
FLOSS_MINLEN = os.getenv("FLOSS_MINLEN", "")
FLOSS_PER_FN = int(os.getenv("FLOSS_PER_FN", "20") or 20)

CAPA_TIMEOUT = int(os.getenv("HUNT_CAPA_TIMEOUT", "180") or 180)
FLOSS_TIMEOUT = int(os.getenv("HUNT_FLOSS_TIMEOUT", "180") or 180)
YARA_TIMEOUT = int(os.getenv("HUNT_YARA_TIMEOUT", "90") or 90)

LLM_ENDPOINT = os.getenv("LLM_ENDPOINT")
LLM_MODEL    = os.getenv("LLM_MODEL")

OUT_DIR = WORK_DIR / "hunt"
OUT_DIR.mkdir(parents=True, exist_ok=True)
MAPPING_PATH = OUT_DIR / "functions.labeled.jsonl"
REPORT_PATH  = OUT_DIR / "report.md"

# ------------ Utility logging ------------
def ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def log(msg: str) -> None:
    print(msg, flush=True)

def stage_start(name: str) -> float:
    t0 = time.time()
    log(f"[hunt] >>> {name}…  ({ts()})")
    return t0

def stage_done(name: str, t0: float, extra: str = "") -> None:
    dt = time.time() - t0
    extra_sfx = f"  {extra}" if extra else ""
    log(f"[hunt] <<< {name} done in {dt:.1f}s{extra_sfx}")

# ------------ Heartbeat ------------
_hb_stop = threading.Event()
def _heartbeat(pfx: str = "[hunt] heartbeat… still analyzing", period: int = 30):
    while not _hb_stop.is_set():
        time.sleep(period)
        if not _hb_stop.is_set():
            log(pfx)

def start_heartbeat():
    _hb_stop.clear()
    t = threading.Thread(target=_heartbeat, daemon=True)
    t.start()
    return t

def stop_heartbeat():
    _hb_stop.set()

# ------------ Discover helpers ------------
def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(0x100)
        if head[:2] != b"MZ":
            return False
        if len(head) < 0x40:
            return False
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little", signed=False)
        return 0 < e_lfanew < 100_000_000
    except Exception:
        return False

def discover_binary(work_root: Path) -> Optional[Path]:
    # precedence: HUNT_BIN → primary_bin.txt → scan root for largest PE (exe/dll/bin)
    env_bin = os.getenv("HUNT_BIN")
    if env_bin and Path(env_bin).is_file():
        return Path(env_bin)

    primary_txt = work_root / "primary_bin.txt"
    if primary_txt.is_file():
        cand = Path(primary_txt.read_text().strip())
        if cand.is_file():
            return cand

    best: Tuple[int, Optional[Path]] = (0, None)
    for p in work_root.iterdir():
        if not p.is_file():
            continue
        lo = p.name.lower()
        if not (lo.endswith(".exe") or lo.endswith(".dll") or lo.endswith(".bin")):
            continue
        if _is_pe(p):
            try:
                sz = p.stat().st_size
            except Exception:
                sz = 0
            if sz > best[0]:
                best = (sz, p)
    return best[1]

def discover_target_out(work_root: Path) -> Optional[Path]:
    # choose the newest "*_out.json" in the work/ root (not recursive)
    cands = sorted(work_root.glob("*_out.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None

# ------------ Load functions ------------
def _safe_len(s: str) -> int:
    return len(s.encode("utf-8", errors="ignore"))

def load_functions_from_target_out(path: Path) -> List[Dict[str, Any]]:
    """
    Expects a JSON file with a top-level dict containing something like 'functions': [...]
    Each function record should have at minimum: name, address (hex or int), and some code snippet field.
    We fall back to simple heuristics on size.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        log(f"[hunt] ERROR: failed to parse JSON from {path}: {e}")
        raise

    # Common shapes:
    funcs = []
    if isinstance(data, dict):
        if "functions" in data and isinstance(data["functions"], list):
            funcs = data["functions"]
        elif "items" in data and isinstance(data["items"], list):
            funcs = data["items"]
        else:
            # try other keys that might hold function dicts
            for k, v in data.items():
                if isinstance(v, list) and v and isinstance(v[0], dict) and ("name" in v[0] or "address" in v[0]):
                    funcs = v
                    break
    elif isinstance(data, list):
        funcs = data

    # Normalize minimal fields
    norm: List[Dict[str, Any]] = []
    for f in funcs:
        if not isinstance(f, dict):
            continue
        name = str(f.get("name") or f.get("func_name") or f.get("symbol") or "sub_unknown")
        addr = f.get("address") or f.get("addr") or f.get("ea")
        if isinstance(addr, str) and addr.lower().startswith("0x"):
            try:
                addr_int = int(addr, 16)
            except Exception:
                addr_int = None
        elif isinstance(addr, (int, float)):
            addr_int = int(addr)
        else:
            addr_int = None

        # choose a snippet field
        snippet = f.get("decompiled") or f.get("pseudocode") or f.get("snippet") or f.get("code") or ""
        snippet = str(snippet)

        # estimate a "size" for ranking
        size = int(f.get("size") or 0)
        if size <= 0:
            size = max(_safe_len(snippet), 1)

        norm.append({
            "name": name,
            "addr": addr_int,
            "snippet": snippet,
            "size": size,
            # carry-through useful evidence if present
            "imports": f.get("imports") or [],
            "strings": f.get("strings") or [],
            "callers": f.get("callers") or [],
            "callees": f.get("callees") or [],
            "module": f.get("module") or f.get("file") or None,
        })
    return norm

# ------------ Enrich (with stage timings) ------------
def has_tool(name: str) -> bool:
    return shutil.which(name) is not None

def _run(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, text=True)
        return (p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return (-999, "", f"timeout after {timeout}s")

def enrich(funcs: List[Dict[str, Any]], bin_path: Path) -> None:
    """
    Lightweight enrichment with timed sub-stages.
    Currently:
      - FLOSS (optional): run once on the binary; attach top strings globally
      - CAPA (optional): run on the binary; attach summary counts
      - YARA (optional): run if rules directory detected; attach hit count
    """
    t0_all = stage_start("enrich()")

    # FLOSS
    t0 = stage_start("FLOSS")
    if ENABLE_FLOSS and has_tool("floss"):
        args = ["floss", "-q", "-j"]
        if FLOSS_MINLEN:
            args += ["--min-length", str(FLOSS_MINLEN)]
        if FLOSS_ARGS:
            args += FLOSS_ARGS.split()
        args.append(str(bin_path))
        rc, out, err = _run(args, FLOSS_TIMEOUT)
        hits = 0
        if rc == 0 and out:
            try:
                j = json.loads(out)
                # collect a few strings for prompt evidence
                strings = []
                for sec in ("stack_strings", "decoded_strings", "static_strings"):
                    ss = j.get(sec) or []
                    for srec in ss[:FLOSS_PER_FN]:
                        s = srec.get("string") if isinstance(srec, dict) else srec
                        if isinstance(s, str):
                            strings.append(s[:120])
                # Attach small sample to each function (non-destructive)
                for f in funcs:
                    f.setdefault("strings", [])
                    f["strings"] = (f["strings"] or []) + strings[:FLOSS_PER_FN]
                hits = len(strings)
            except Exception as e:
                log(f"[floss] warn: failed to parse output: {e}")
        else:
            log(f"[floss] skipped rc={rc} err={err.strip()[:120]}")
        stage_done("FLOSS", t0, f"(strings≈{hits})")
    else:
        stage_done("FLOSS", t0, "(disabled or tool missing)")

    # CAPA
    t0 = stage_start("CAPA")
    capa_hits = 0
    if ENABLE_CAPA and has_tool("capa"):
        rc, out, err = _run(["capa", "-q", "-j", str(bin_path)], CAPA_TIMEOUT)
        if rc == 0 and out:
            try:
                j = json.loads(out)
                rules = j.get("rules") or {}
                capa_hits = len(rules)
                # Just stash a summary on each func for now
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
        # try a repo-local rules directory
        repo_rules = Path("tools/yara")
        rules_dir = os.getenv("YARA_RULES_DIR", str(repo_rules if repo_rules.is_dir() else ""))
        if rules_dir and Path(rules_dir).exists():
            rc, out, err = _run(["yara", "-r", rules_dir, str(bin_path)], YARA_TIMEOUT)
            if rc in (0, 1) and out:
                # each matching line is a hit
                yara_hits = len([ln for ln in out.splitlines() if ln.strip()])
                for f in funcs:
                    f.setdefault("yara_hits", yara_hits)
            else:
                log(f"[yara] no matches or error rc={rc} err={err.strip()[:200]}")
            stage_done("YARA", t0, f"(hits≈{yara_hits})")
        else:
            stage_done("YARA", t0, "(no rules directory)")
    else:
        stage_done("YARA", t0, "(disabled or tool missing)")

    stage_done("enrich()", t0_all)

# ------------ Report ------------
def write_report(path: Path, funcs: List[Dict[str, Any]], labeled: Optional[List[Dict[str, Any]]] = None) -> None:
    lines = []
    lines.append(f"# Function Hunt Report\n")
    lines.append(f"- Generated: {ts()}")
    lines.append(f"- Functions considered: {len(funcs)}")
    if labeled is not None:
        named = sum(1 for r in labeled if r and r.get("name"))
        lines.append(f"- Labeled by LLM: {named}/{len(labeled)}")
    lines.append("")
    lines.append("| addr | original | label | confidence |")
    lines.append("|---:|---|---|---:|")
    for i, f in enumerate(funcs[: min(len(funcs), 2000)]):
        orig = f.get("name") or "sub_unknown"
        addr = f.get("addr")
        addr_s = f"0x{addr:X}" if isinstance(addr, int) else "-"
        lab = ""
        conf = ""
        if labeled and i < len(labeled) and labeled[i]:
            lab = labeled[i].get("name") or ""
            conf = f"{labeled[i].get('confidence', '')}"
        lines.append(f"| {addr_s} | {orig} | {lab} | {conf} |")
    path.write_text("\n".join(lines), encoding="utf-8")
    log(f"[hunt] wrote {path}  (functions: {len(funcs)})")

# ------------ Main ------------
def main() -> int:
    print(f"[hunt] work dir: {WORK_DIR}", flush=True)

    # Discover inputs
    log("[hunt] starting discover…")
    t0 = time.time()
    bin_path = discover_binary(WORK_DIR)
    tgt_out  = discover_target_out(WORK_DIR)

    if not bin_path or not bin_path.exists():
        log(f"[hunt] ERROR: binary not found at {WORK_DIR} root. Set HUNT_BIN or place *.exe|*.dll|*.bin in work/")
        return 2
    if not tgt_out or not tgt_out.exists():
        log(f"[hunt] ERROR: target_out JSON not found at {WORK_DIR} root (expected '*_out.json').")
        return 2

    log(f"[hunt] binary     : {bin_path}")
    log(f"[hunt] target_out : {tgt_out}")
    log(f"[hunt] out dir    : {OUT_DIR}")

    # Load + normalize functions
    hb = start_heartbeat()
    try:
        funcs = load_functions_from_target_out(tgt_out)
        log(f"[hunt] discovered: {len(funcs)}")
        # Filter by min size
        if HUNT_MIN_SIZE > 0:
            before = len(funcs)
            funcs = [f for f in funcs if int(f.get("size") or 0) >= HUNT_MIN_SIZE]
            log(f"[hunt] filtered by HUNT_MIN_SIZE={HUNT_MIN_SIZE}: {before} → {len(funcs)}")

        # Sort by size desc; take top N if requested
        funcs.sort(key=lambda f: int(f.get("size") or 0), reverse=True)
        if HUNT_TOPN > 0 and len(funcs) > HUNT_TOPN:
            log(f"[hunt] taking top {HUNT_TOPN} by size (HUNT_TOPN) → {HUNT_TOPN}")
            funcs = funcs[:HUNT_TOPN]
        log(f"[hunt] functions normalized: {len(funcs)}")
    finally:
        # keep heartbeat on for enrich phase
        pass

    # Enrich (with timed sub-stages)
    enrich(funcs, bin_path)
    stop_heartbeat()  # stop after enrich; LLM stage is already chatty via label.py

    # LLM label (label.py handles caching/resume and progress)
    t0_llm = stage_start("llm_label_batch()")
    labeled = llm_label_batch(funcs, LLM_ENDPOINT, LLM_MODEL)  # returns list[dict] aligned with funcs
    stage_done("llm_label_batch()", t0_llm)

    # Write mapping JSONL (one line per function)
    with MAPPING_PATH.open("w", encoding="utf-8") as fh:
        for f, lab in zip(funcs, labeled):
            rec = {
                "_orig_name": f.get("name"),
                "addr": f.get("addr"),
                "name": (lab or {}).get("name") or f.get("name"),
                "confidence": (lab or {}).get("confidence", None),
                "tags": (lab or {}).get("tags", None),
                "inputs": (lab or {}).get("inputs", None),
                "outputs": (lab or {}).get("outputs", None),
                "side_effects": (lab or {}).get("side_effects", None),
                "evidence": (lab or {}).get("evidence", None),
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Write a quick report
    log("[hunt] writing report…")
    write_report(REPORT_PATH, funcs, labeled)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("[hunt] interrupted by user")
        sys.exit(130)

