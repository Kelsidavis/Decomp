#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export PYTHONUNBUFFERED=1

# -------- robust logging --------
WORK_DIR="/work"
if ! mkdir -p "$WORK_DIR" 2>/dev/null || ! test -w "$WORK_DIR"; then
  echo "[WARN] /work not writable or not mounted; falling back to /tmp/work"
  WORK_DIR="/tmp/work"
  mkdir -p "$WORK_DIR"
fi
LOG="$WORK_DIR/run.$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[!] Error on line $LINENO: $BASH_COMMAND"; echo "[!] See log: $LOG"; exit 1' ERR
[[ "${DEBUG:-0}" == "1" ]] && set -x

# -------- required env --------
: "${GHIDRA_HOME:?GHIDRA_HOME not set}"
: "${BINARY_PATH:?BINARY_PATH not set}"
: "${OUT_JSON:?OUT_JSON not set}"
: "${REPORT_MD:?REPORT_MD not set}"
: "${GHIDRA_PROJECT_DIR:?GHIDRA_PROJECT_DIR not set}"
: "${GHIDRA_PROJECT_NAME:?GHIDRA_PROJECT_NAME not set}"

HUMANIZE_MODE="${HUMANIZE_MODE:-apply}"   # off|suggest|apply
BUILD_RECOVERED="${BUILD_RECOVERED:-0}"   # 1 to run make in applied project
CODE_LANG="${CODE_LANG:-auto}"            # auto|c|cpp

proj="$WORK_DIR/recovered_project"
EXTRA_ARGS=${GHIDRA_EXTRA_ARGS:-}

# Clean per-run Ghidra project to avoid “conflicting program file in project”
echo "[prep] Clearing project dir: $GHIDRA_PROJECT_DIR"
rm -rf "$GHIDRA_PROJECT_DIR" || true
mkdir -p "$GHIDRA_PROJECT_DIR" "$proj"

echo "[1/6] Ghidra → ${OUT_JSON}"
analyzeHeadless "$GHIDRA_PROJECT_DIR" "$GHIDRA_PROJECT_NAME" \
  -import "$BINARY_PATH" \
  $EXTRA_ARGS \
  -max-cpu "${THREAD_COUNT:-10}" \
  -analysisTimeoutPerFile 300 \
  -scriptPath /app/ghidra_scripts \
  -postScript dump_functions.py "$OUT_JSON"

echo "[1b] Dumping imports → $WORK_DIR/imports.json"
analyzeHeadless "$GHIDRA_PROJECT_DIR" "$GHIDRA_PROJECT_NAME" \
  -import "$BINARY_PATH" $EXTRA_ARGS \
  -overwrite \
  -max-cpu "${THREAD_COUNT:-10}" \
  -scriptPath /app/ghidra_scripts \
  -postScript dump_imports.py || echo "[WARN] dump_imports.py failed"

echo "[2/6] LLM explain → ${REPORT_MD}"
python3 /app/explain_with_llm.py "$OUT_JSON" --out "$REPORT_MD"

# --- language auto-detect (only if CODE_LANG=auto) ---
if [ "$CODE_LANG" = "auto" ]; then
  CODE_LANG=$(python3 - <<PY
import re, pathlib
text=""
for p in (pathlib.Path("$OUT_JSON"), pathlib.Path("$REPORT_MD")):
    try: text += p.read_text(errors="ignore") + "\n"
    except: pass
cpp_signals = [
    r"\?\?(?:0|1|_R|_7)", r"\?[^ \n@]*@@", r"_Z[a-zA-Z0-9_]+",
    r"\bstd::", r"\bbasic_string\b", r"\bvector<", r"\bstd::vector\b",
    r"\btypeinfo\b", r"\bvtable\b", r"\bvtbl\b", r"\b__thiscall\b",
]
print("cpp" if any(re.search(p, text) for p in cpp_signals) else "c")
PY
)
  echo "[lang] Auto-detected: $CODE_LANG"
fi

echo "[3/6] Report → code scaffold @ ${proj}"
python3 /app/report_to_code.py "$REPORT_MD" --out "$proj" --lang "$CODE_LANG"

echo "[4/6] Dumping PE resources → $proj/assets/pe_resources"
mkdir -p "$proj/assets/pe_resources"
# Use -overwrite to avoid “conflicting program file in project” on the 2nd pass
if ! analyzeHeadless "$GHIDRA_PROJECT_DIR" "$GHIDRA_PROJECT_NAME" \
    -import "$BINARY_PATH" $EXTRA_ARGS -overwrite \
    -max-cpu "${THREAD_COUNT:-10}" \
    -scriptPath /app/ghidra_scripts \
    -postScript dump_pe_resources.py "$proj/assets/pe_resources"; then
  echo "[WARN] dump_pe_resources.py failed; continuing"
fi
echo "[stats] pe_resources files: $(find "$proj/assets/pe_resources" -type f 2>/dev/null | wc -l)"

echo "[4b/6] Normalizing PE resources (BMP/ICO)"
if ! python3 /app/fix_pe_resources.py "$proj/assets/pe_resources"; then
  echo "[WARN] fix_pe_resources.py failed; continuing"
fi

echo "[5/6] Carving by magic → $proj/assets"
if ! python3 /app/carve_assets.py "$BINARY_PATH" "$proj/assets"; then
  echo "[WARN] carve_assets.py failed; continuing"
fi

echo "[6/6] Embedding assets into code"
python3 /app/embed_assets.py "$proj/assets" "$proj"
echo "[stats] all asset files: $(find "$proj/assets" -type f 2>/dev/null | wc -l)"

# keep the report inside the project BEFORE humanize so it can read it
cp -f "$REPORT_MD" "$proj/"

echo "[✓] Recovered project ready at: $proj"
echo "    - include/recovered.h + include/resources.h"
echo "    - src/*.c(pp) + src/resources_embedded.c"
echo "    - assets/* (carved + PE resources) + report.md"

# Optional: verify/repair assets if script exists
if [ -f /app/verify_and_repair_assets.py ]; then
  echo "[6b] Verifying and repairing assets"
  python3 /app/verify_and_repair_assets.py "$proj/assets" || true
fi

case "$HUMANIZE_MODE" in
  off)
    echo "[*] HUMANIZE_MODE=off — skipping humanization"
    ;;
  suggest)
    echo "[*] Humanizing (suggest phase) → recovered_project_human/"
    python3 /app/humanize_project.py \
      "$proj" \
      --out "$WORK_DIR/recovered_project_human" \
      --outjson "$OUT_JSON" || true
    ;;
  apply)
    echo "[*] Humanizing (apply phase) → recovered_project_human_applied/"
    python3 /app/humanize_project.py \
      "$proj" \
      --out "$WORK_DIR/recovered_project_human_applied" \
      --outjson "$OUT_JSON" \
      --apply || true
    if [ "${BUILD_RECOVERED}" = "1" ]; then
      echo "[*] Building recovered_project_human_applied/"
      ( cd "$WORK_DIR/recovered_project_human_applied" && make ) || echo "[!] Build failed (expected during early stubs)"
    fi
    ;;
  *)
    echo "[!] Unknown HUMANIZE_MODE='$HUMANIZE_MODE' (use off|suggest|apply) — skipping"
    ;;
esac

echo "[*] Generating Windows build from recovered_project"
python3 /app/generate_windows_build.py "$proj" "$WORK_DIR/imports.json" || true

echo "[*] Building recovered_project_win (MinGW)"
cmake -G "Unix Makefiles" -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
      -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
      -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
      -S "$WORK_DIR/recovered_project_win" -B "$WORK_DIR/recovered_project_win/build" >>"$WORK_DIR/cmake_win.log" 2>&1 || true
cmake --build "$WORK_DIR/recovered_project_win/build" -j "${THREAD_COUNT:-10}" >>"$WORK_DIR/cmake_win.log" 2>&1 || true

echo "[✓] Done. Log captured at: $LOG"

