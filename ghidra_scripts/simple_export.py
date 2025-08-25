#@category Decomp/Export
# Headless exporter: dump function metadata + (bounded) decompiler text with checkpoints & resume.
#
# Env knobs (read via os.environ):
#   EXPORT_FLUSH_EVERY   : how often to rewrite OUT_JSON (valid JSON), default 500
#   EXPORT_TOPN          : limit to top-N functions by body size (0 = all), default 0
#   EXPORT_MAX_SECONDS   : soft overall budget (0 = no limit), default 0  (we still obey external wrapper timeout)
#   DECOMPILE_SEC        : per-function decompile timeout seconds, default 12
#   SKIP_PSEUDO          : "1" to skip decompile text (metadata-only), default "0"
#
# Args from AnalyzeHeadless:
#   <OUT_JSON_PATH>
#
# Sidecar for resume:
#   <OUT_JSON_PATH>.addrs.txt   # list of addresses exported (one per line)
#
# Progress lines:
#   "[export] progress <count> functions..."
#
# This script is Jython and uses Ghidra APIs.

import os, sys, time, json, hashlib
from java.lang import System
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.flatapi import FlatProgramAPI

# -------- util --------
def getenv(k, default=None):
    v = os.environ.get(k)
    if v is None:
        v = System.getenv(k)  # in case only Java env is set
    return default if v is None else v

def to_int(s, dv):
    try: return int(str(s).strip())
    except: return dv

def now_ts():
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def addr_str(fn):
    try:
        return fn.getEntryPoint().toString()
    except:
        return "0x0"

def fn_size(fn):
    try:
        return fn.getBody().getNumAddresses()
    except:
        return 0

def read_sidecar(side_path):
    done = set()
    try:
        f = open(side_path, "r")
        for ln in f:
            ln = ln.strip()
            if ln:
                done.add(ln)
        f.close()
    except:
        pass
    return done

def append_sidecar(side_path, addrs):
    if not addrs: return
    f = open(side_path, "a")
    for a in addrs: f.write(a + "\n")
    f.close()

def write_json_safe(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2)
    # atomic-ish
    try:
        os.replace(tmp, path)
    except:
        os.rename(tmp, path)

# -------- main --------
def main():
    out_json = None
    if len(sys.argv) >= 2:
        out_json = sys.argv[1]
    if not out_json:
        out_json = getenv("OUT_JSON", "/work/snapshots/out.json")
    out_json = str(out_json)

    flush_every   = to_int(getenv("EXPORT_FLUSH_EVERY", "500"), 500)
    topn          = to_int(getenv("EXPORT_TOPN", "0"), 0)
    max_seconds   = to_int(getenv("EXPORT_MAX_SECONDS", "0"), 0)
    decomp_sec    = to_int(getenv("DECOMPILE_SEC", "12"), 12)
    skip_pseudo   = str(getenv("SKIP_PSEUDO", "0")).strip() in ("1","true","yes","on")

    sidecar = out_json + ".addrs.txt"
    t_start = time.time()

    monitor = ConsoleTaskMonitor()

    prog = currentProgram
    api  = FlatProgramAPI(prog)

    # Build function list
    fn_mgr = prog.getFunctionManager()
    it = fn_mgr.getFunctions(True)  # forward
    fns = []
    while it.hasNext() and not monitor.isCancelled():
        fns.append(it.next())

    # sort by body size desc for best ROI if topn > 0
    fns.sort(key=lambda f: fn_size(f), reverse=True)
    if topn > 0 and topn < len(fns):
        fns = fns[:topn]

    # Resume: read sidecar for already-exported addresses
    done_addrs = read_sidecar(sidecar)

    # Decompiler setup
    ifc = None
    if not skip_pseudo:
        ifc = DecompInterface()
        opts = DecompileOptions()
        try:
            # per-function timeout (seconds)
            opts.setTimeout(decomp_sec)
        except:
            pass
        ifc.setOptions(opts)
        if not ifc.openProgram(prog):
            # if fails, fall back to metadata-only
            ifc = None
            skip_pseudo = True

    # Program meta
    md5 = ""
    try:
        cm = prog.getMemory()
        bf = cm.getAllInitializedAddressSet().getNumAddresses()
        md5 = str(prog.getExecutableMD5()) if prog.getExecutableMD5() else ""
    except:
        pass

    meta = {
        "program_name": prog.getName(),
        "lang": str(prog.getLanguage().getLanguageID()),
        "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(prog.getImageBase()),
        "md5": md5,
        "export_ts": now_ts(),
        "flush_every": flush_every,
        "topn": topn,
        "decompile_sec": decomp_sec,
        "skip_pseudo": skip_pseudo,
    }

    exported = []
    exported_addrs_batch = []
    total = len(fns)
    count = 0

    def flush():
        if not exported:
            # if resuming and nothing new yet, but maybe an old file exists
            if os.path.isfile(out_json):
                return
        obj = {
            "meta": meta,
            "functions": exported
        }
        write_json_safe(out_json, obj)

    for fn in fns:
        if monitor.isCancelled():
            break

        a = addr_str(fn)
        if a in done_addrs:
            continue

        # time budget?
        if max_seconds > 0 and (time.time() - t_start) >= max_seconds:
            break

        # collect minimal metadata
        rec = {
            "name": fn.getName(),
            "addr": a,
            "size": fn_size(fn)
        }

        # decompile (optional, with bounded time)
        if not skip_pseudo and ifc is not None:
            try:
                res = ifc.decompileFunction(fn, decomp_sec, monitor)
                if res and res.getDecompiledFunction():
                    code = res.getDecompiledFunction().getC()
                    # trim very long blocks to keep JSON manageable
                    if code is not None and len(code) > 20000:
                        code = code[:20000] + "\n/* ...truncated... */\n"
                    rec["decomp"] = code
                else:
                    rec["decomp"] = None
            except:
                rec["decomp"] = None
        else:
            rec["decomp"] = None

        exported.append(rec)
        exported_addrs_batch.append(a)
        count += 1

        if (count % 500) == 0:
            print("[export] progress %d functions..." % count)
            flush()
            append_sidecar(sidecar, exported_addrs_batch)
            exported_addrs_batch = []

        # obey external timeout wrapper if present
        # (no direct signal visibility here; rely on wrapper to kill us)

    # final flush
    flush()
    append_sidecar(sidecar, exported_addrs_batch)
    print("[export] done, total exported: %d" % count)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("[export] ERROR:", e)
        sys.exit(1)

