import json, os, shutil, subprocess
from pathlib import Path
try:
    # expected path for your new helper
    from tools.function_hunt.enrich_capa import run_capa_json as _capa_run_json
except Exception:
    _capa_run_json = None

def _strings(path):
    if not shutil.which("strings"):
        return []
    out = subprocess.run(["strings", "-n", "4", path], capture_output=True, text=True)
    return [s.strip() for s in out.stdout.splitlines() if s.strip()][:2000]

def _pe_imports(path):
    # Prefer rabin2 if available; otherwise empty (we keep it robust).
    if shutil.which("rabin2"):
        r = subprocess.run(["rabin2","-i", path], capture_output=True, text=True)
        names = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if parts and parts[-1].count(".") >= 1:
                names.append(parts[-1])
        return names[:512]
    return []

def _run_capa(path):
    """
    Run CAPA with project rules + signatures and an env-driven timeout.
    Uses tools.function_hunt.enrich_capa if available; otherwise falls back
    to a local runner that honors CAPA_TIMEOUT and your PATH timeout shim.
    """
    if _capa_run_json is not None:
        try:
            return _capa_run_json(path)
        except Exception:
            pass
    # Fallback: call via timeout shim and pass rules/sigs explicitly
    capa = shutil.which("capa")
    tout = shutil.which("timeout") or "/usr/bin/timeout"
    if not capa:
        return {}
    rules = os.getenv("CAPA_RULES", "rules/capa")
    sigs  = os.getenv("CAPA_SIGNATURES", os.getenv("CAPA_DATADIR", "rules/sigs"))
    secs  = str(int(float(os.getenv("CAPA_TIMEOUT", "600"))))
    cmd   = [tout, secs, capa, "-j", "-r", rules, "--signatures", sigs, "--", path]
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(r.stdout or "{}")
    except Exception:
        return {}

def _run_yara(path, rules_dir="rules"):
    if not shutil.which("yara"):
        return []
    hits = []
    for root, _, files in os.walk(rules_dir):
        for f in files:
            if f.endswith((".yar",".yara")):
                r = subprocess.run(["yara", os.path.join(root,f), path],
                                   capture_output=True, text=True)
                hits.extend([ln.strip() for ln in r.stdout.splitlines() if ln.strip()])
    return hits[:200]

def enrich(funcs, enable_capa, enable_yara, bin_path):
    bin_path = str(bin_path)
    strings = _strings(bin_path)
    imports = _pe_imports(bin_path)
    capa_res = _run_capa(bin_path) if enable_capa else {}
    yara_hits = _run_yara(bin_path) if enable_yara else []

    for f in funcs:
        f.setdefault("signals", {})
        f["strings"] = strings[:100]      # keep prompts small
        f["imports"] = imports[:100]
        f["signals"]["capa"] = capa_res.get("rules", {}) if capa_res else {}
        f["signals"]["yara"] = yara_hits

    # persist enriched snapshot next to report
    run_dir = Path(bin_path).resolve().parent
    hunt_dir = run_dir / "hunt"
    hunt_dir.mkdir(exist_ok=True)
    out = hunt_dir / "functions.enriched.jsonl"
    with out.open("w") as w:
        for f in funcs:
            w.write(json.dumps(f)+"\n")

