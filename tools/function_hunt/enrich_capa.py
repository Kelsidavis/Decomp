# tools/function_hunt/enrich_capa.py
import os, subprocess, shlex

def which(x):
    from shutil import which as _w
    return _w(x) or x

BIN         = os.getenv("HUNT_BIN", "work/WoW.exe")
CAPA_RULES  = os.getenv("CAPA_RULES", "rules/capa")
CAPA_SIGS   = os.getenv("CAPA_SIGNATURES", os.getenv("CAPA_DATADIR", "rules/sigs"))
CAPA_BIN    = "./bin/capa"  # use project wrapper explicitly
TIMEOUT_BIN = which("timeout")  # resolves to your PATH shim, not /usr/bin/timeout
CAPA_TIMEOUT= str(int(float(os.getenv("CAPA_TIMEOUT", "600"))))

# Build command; always pass rules + signatures; timeout from env
cmd = [
    TIMEOUT_BIN, CAPA_TIMEOUT,
    CAPA_BIN, "-j", "-r", CAPA_RULES, "--signatures", CAPA_SIGS,
    "--", BIN
]

def run_capa_json(path):
    """Run capa with JSON output, return parsed result."""
    import json
    cmd_for_path = [
        TIMEOUT_BIN, CAPA_TIMEOUT,
        CAPA_BIN, "-j", "-r", CAPA_RULES, "--signatures", CAPA_SIGS,
        "--", path
    ]
    try:
        out = subprocess.run(cmd_for_path, capture_output=True, text=True)
        if out.returncode == 0:
            return json.loads(out.stdout or "{}")
        else:
            return {}
    except Exception:
        return {}

if __name__ == "__main__":
    print(f"[capa] exec: {' '.join(shlex.quote(c) for c in cmd)}")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
        rc  = out.returncode
        if rc == 0:
            print(out.stdout.rstrip())
        else:
            print(out.stdout.rstrip())
            print(out.stderr.rstrip())
            raise SystemExit(rc)
    except FileNotFoundError as e:
        print(f"[capa] ERROR: {e}")
        raise

