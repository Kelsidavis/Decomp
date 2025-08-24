import json, os, shutil, subprocess
from pathlib import Path

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
    if shutil.which("capa"):
        r = subprocess.run(["capa","-j", path], capture_output=True, text=True)
        try: return json.loads(r.stdout or "{}")
        except Exception: return {}
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

