# Decomp — Ghidra + LLM decompilation pipeline

Decomp wires **Ghidra (headless)**, a set of **Python enrichers**, and a local **LLM server** into a single workflow that can:

* analyze a Windows PE binary (`.exe`)
* export functions + metadata from Ghidra
* label/classify functions with an LLM
* scaffold a compilable project (C/C++)
* (optionally) re‑implement bodies with another LLM profile

The one‑shot entry point is **`./full_run.sh`**.

---

## Quick start

### Prereqs

* **Docker** (runs the Ghidra headless exporter)
* **Python 3.10+** on host (`pip install -r requirements.txt` if present)
* **GPU optional** (local LLM via llama.cpp, controlled by `scripts/llm/llmctl.sh`)

### Build the Ghidra image

```bash
# If BuildKit complains about buildx, either install buildx or use classic builder:
DOCKER_BUILDKIT=0 docker build --pull --no-cache -t decomp-ghidra-llm:latest .
```

### Place your binary

```bash
mkdir -p work
cp /path/to/target.exe work/
```

### Start / switch the local LLM

```bash
# Ensures a single llama.cpp server on :8080 and exports env (LLM_ENDPOINT, LLM_MODEL)
scripts/llm/llmctl.sh switch llm4d
```

### Run the full pipeline

```bash
./full_run.sh --exe work/target.exe
```

Logs: `work/logs/full_run.YYYYmmdd-HHMMSS.log` and `work/logs/latest_full_run.log` (symlink).

---

## What the pipeline does

1. **pre‑unpack** — unwraps self‑extracting archives / nested binaries (to `work/extracted/`).
2. **export (docker)** — runs Ghidra headless in a container and writes `*_out.json` into `work/snapshots/`.
3. **analyze / label** — feeds exported functions to the LLM (profile `LLM_PROFILE_LABEL`) and writes:

   * `work/hunt/functions.labeled.jsonl`
   * `work/hunt/report.md`
4. **humanize** — optional AST‑safe renaming into `work/recovered_project_human/` using the mapping.
5. **re‑implement (optional)** — uses profile `LLM_PROFILE_REIMPL` to generate function bodies.

Common output tree:

```
work/
  hunt/
    functions.labeled.jsonl
    report.md
  snapshots/
    <base>_out.json
  recovered_project/
    include/
    src/
    assets/
  recovered_project_human/
  recovered_project_reimpl/
  logs/
```

---

## Rules & enrichment (optional but recommended)

You can enrich with **FLOSS** (decoded strings), **CAPA** (behavioral rules), and **YARA**:

```
rules/
  capa/   # CAPA rules
  sigs/   # CAPA signatures pack
  yara/   # YARA rules
```

Environment knobs (defaults in parentheses):

* `CAPA_RULES` (`rules/capa`)
* `CAPA_SIGNATURES` **or** `CAPA_DATADIR` (`rules/sigs`)
* `YARA_RULES_DIR` (`rules/yara`)
* `ENABLE_CAPA=1`, `ENABLE_YARA=1`, `ENABLE_FLOSS=1`

If a directory is missing, the stage is disabled gracefully with a WARN.

---

## Timeouts & wrappers

To avoid premature kills and probe races, the pipeline uses small shims and envs:

* `FLOSS_TIMEOUT` (seconds) → FLOSS extraction (also mirrored to `HUNT_FLOSS_TIMEOUT`)
* `CAPA_TIMEOUT` (seconds)  → CAPA scans
* `LLM_GRACE` (seconds)     → sleep after spawning the LLM server before the first health probe

**Note:** the repo provides `bin/` wrappers so `timeout`, `capa`, and `yara` resolve via **PATH** and honor these envs. If any code references `/usr/bin/timeout`, replace with `timeout` so the shim is used.

---

## Windows API detection & linking

Decomp includes an API database and resolver to generate declarations and link flags.

* **Signatures DB:** `tools/api_signatures.json`

  * Keeps your **FMOD** + Win32 sets (e.g., `FSOUND_*`, `kernel32`, `user32`).
  * Can include families/regex (e.g., `^FSOUND_`, `^Nt.*`, `^WSA.*`).
* **Resolver:** `tools/resolve_external_apis.py`

  * Scans `recovered_project/src` for function identifiers and (optionally) import names from `*_out.json`.
  * Normalizes Win `A/W` suffixes for matching.
  * Emits:

    * `work/recovered_project/include/external_apis.h` (extern decls, system/vendor headers)
    * `work/recovered_project/external_linkage.json` (selected libs, `-l…` flags, headers)

Run manually:

```bash
python3 tools/resolve_external_apis.py work/recovered_project
cat work/recovered_project/external_linkage.json
```

Your build step can read `external_linkage.json` and append `ldflags` to the generated Makefile (Windows: `-lkernel32 -luser32 -lfmod_vc`, etc.).

---

## Key scripts & dirs

* `full_run.sh` — one‑shot pipeline driver
* `scripts/llm/llmctl.sh` — manage local LLM profiles (start/stop/switch/env)
* `profiles/` — example model envs used by `llmctl`
* `ghidra_scripts/` — headless exporter invoked inside the container
* `tools/` — enrichment & project helpers (autodiscover, humanize, reimplement, API resolver)

---

## Common env knobs

Pipeline / exporter:

* `WORK_DIR` (`work`), `HUNT_TOPN`, `HUNT_MIN_SIZE`, `HUNT_CACHE=1`, `HUNT_RESUME=1`
* `GHIDRA_IMAGE` (`decomp-ghidra-llm:latest`)
* `GHIDRA_TIMEOUT` (sec), `EXPORT_FLUSH_EVERY`, `DECOMPILE_SEC`, `EXPORT_TOPN`
* `SKIP_PSEUDO=0` (1 = metadata‑only export)

LLM / profiles:

* `LLM_PROFILE_LABEL=llm4d`, `LLM_PROFILE_REIMPL=qwen14`
* `LLM_ENDPOINT`, `LLM_MODEL` (exported by `llmctl env <profile>`)
* `REIMPL_ENABLE=1`, `REIMPL_MIN_CONF`, `REIMPL_MAX_FNS`

---

## Troubleshooting

* **“Don’t source this script.”** → Run as `./full_run.sh`, not via `.`/`source`.
* **First probe to :8080 fails.** → Increase `LLM_GRACE` (e.g., `LLM_GRACE=1.2`).
* **CAPA still stops at 180s.** → Ensure no code calls `/usr/bin/timeout` directly; the PATH shim enforces `CAPA_TIMEOUT`.
* **BuildKit/buildx error.** → Use `DOCKER_BUILDKIT=0 docker build …` or install Docker buildx.

---

## Contributing

PRs welcome: exporter improvements, new enrichers, rule packs, profile configs, resolver extensions (Linux/macOS, more SDKs). Please keep runs reproducible and prefer small sample binaries for tests.

---
