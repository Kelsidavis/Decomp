#!/usr/bin/env bash
# entrypoint.sh — run Ghidra analyzeHeadless to export *_out.json (no python required)
set -Eeuo pipefail

: "${BINARY_PATH:=}"                          # optional; prefer /work/primary_bin.txt if unset
: "${OUT_JSON:=}"                             # default computed from chosen binary
: "${GHIDRA_SCRIPT:=simple_export.py}"
: "${GHIDRA_SCRIPT_DIR:=/scripts}"
: "${GHIDRA_PROJECT_DIR:=/tmp/gh_proj}"       # ephemeral to avoid host perms
: "${GHIDRA_PROJECT_NAME:=autoproj}"
: "${GHIDRA_TIMEOUT:=1800}"
: "${GHIDRA_MAXMEM:=4G}"
: "${HOST_WORK_DIR:=}"                        # optional hint to map host abs path → /work
: "${HOME:=/tmp/gh_user}"
: "${XDG_CONFIG_HOME:=$HOME/.config}"

mkdir -p "$HOME" "$XDG_CONFIG_HOME" || true
export GHIDRA_MAXMEM HOME XDG_CONFIG_HOME

log(){ printf '[%s] %s\n' "$(date +%T)" "$*" >&2; }

# --- choose binary: prefer /work/primary_bin.txt if present ---
if [[ -z "${BINARY_PATH}" && -f "/work/primary_bin.txt" ]]; then
  BINARY_PATH="$(</work/primary_bin.txt)"
fi

# Map obvious host abs paths → /work/… if needed
rebase_to_work() {
  local p="$1"
  [[ "$p" == /work/* ]] && { echo "$p"; return; }
  if [[ -n "$HOST_WORK_DIR" && "$p" == "$HOST_WORK_DIR"/* ]]; then
    echo "/work/${p#"$HOST_WORK_DIR/"}"; return
  fi
  if [[ "$p" == *"/work/"* ]]; then
    local tail="/${p#*"/work/"}"
    echo "/work/${tail#/work/}"; return
  fi
  echo "$p"
}
if [[ -n "$BINARY_PATH" && ! -e "$BINARY_PATH" ]]; then
  BINARY_PATH="$(rebase_to_work "$BINARY_PATH")"
fi

# If still missing, try best-effort discovery within /work
if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
  log "WARN: no valid BINARY_PATH; scanning /work for *.exe candidates…"
  cand="$(find /work -maxdepth 3 -type f -iname '*.exe' -printf '%s %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{sub($1 FS,"");print}')"
  if [[ -n "$cand" && -f "$cand" ]]; then
    BINARY_PATH="$cand"
    log "INFO: auto-selected candidate: $BINARY_PATH"
  fi
fi
if [[ -z "$BINARY_PATH" || ! -f "$BINARY_PATH" ]]; then
  log "ERROR: BINARY_PATH not set and /work/primary_bin.txt missing or invalid."
  exit 2
fi

# --- PE sanity: check 'MZ' signature (no Python) ---
is_pe() { local f="$1"; local sig; sig="$(od -An -t x1 -N2 "$f" 2>/dev/null | tr -d ' \n')"; [[ "$sig" == "4d5a" || "$sig" == "4D5A" ]]; }
if ! is_pe "$BINARY_PATH"; then
  log "ERROR: selected binary does not look like a PE (no MZ): $BINARY_PATH"
  exit 2
fi

# compute OUT_JSON if not provided
if [[ -z "${OUT_JSON}" ]]; then
  base="$(basename "${BINARY_PATH%.*}")"
  OUT_JSON="/work/snapshots/${base}_out.json"
fi

# find exporter script
if [[ ! -f "${GHIDRA_SCRIPT_DIR}/${GHIDRA_SCRIPT}" ]]; then
  if [[ -f "/app/ghidra_scripts/${GHIDRA_SCRIPT}" ]]; then
    GHIDRA_SCRIPT_DIR="/app/ghidra_scripts"
  else
    log "ERROR: exporter script not found: ${GHIDRA_SCRIPT} in ${GHIDRA_SCRIPT_DIR} or /app/ghidra_scripts"
    exit 3
  fi
fi

# ghidra sanity
if [[ -z "${GHIDRA_HOME:-}" || ! -x "${GHIDRA_HOME}/support/analyzeHeadless" ]]; then
  log "ERROR: analyzeHeadless not found (GHIDRA_HOME='${GHIDRA_HOME:-<unset>}')"
  exit 4
fi

mkdir -p "$(dirname "${OUT_JSON}")" "${GHIDRA_PROJECT_DIR}"

log "Ghidra:   ${GHIDRA_HOME}"
log "Java:     JAVA_HOME=${JAVA_HOME:-<unset>}  GHIDRA_JAVA_HOME=${GHIDRA_JAVA_HOME:-<unset>}"
log "Binary:   ${BINARY_PATH}"
log "Exporter: ${GHIDRA_SCRIPT_DIR}/${GHIDRA_SCRIPT}"
log "Output:   ${OUT_JSON}"
log "Project:  ${GHIDRA_PROJECT_DIR} : ${GHIDRA_PROJECT_NAME}"
log "Timeout:  ${GHIDRA_TIMEOUT}s | MaxMem: ${GHIDRA_MAXMEM}"
log "HOME:     ${HOME}  XDG_CONFIG_HOME: ${XDG_CONFIG_HOME}"

set +e
timeout "${GHIDRA_TIMEOUT}" "${GHIDRA_HOME}/support/analyzeHeadless" \
  "${GHIDRA_PROJECT_DIR}" "${GHIDRA_PROJECT_NAME}" \
  -import "${BINARY_PATH}" \
  -scriptPath "${GHIDRA_SCRIPT_DIR}" \
  -postScript "${GHIDRA_SCRIPT}" "${OUT_JSON}" \
  -analysisTimeoutPerFile "${GHIDRA_TIMEOUT}" \
  -deleteProject
rc=$?
set -e

if (( rc != 0 )); then
  log "ERROR: analyzeHeadless rc=${rc}"
  exit "$rc"
fi
if [[ ! -s "${OUT_JSON}" ]]; then
  log "ERROR: export did not produce JSON: ${OUT_JSON}"
  exit 5
fi

log "[export] wrote ${OUT_JSON} ($(wc -c <"${OUT_JSON}" 2>/dev/null || echo 0) bytes)"

