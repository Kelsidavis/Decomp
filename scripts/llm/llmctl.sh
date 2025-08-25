#!/usr/bin/env bash
# scripts/llm/llmctl.sh
# Control a single llama-server on port 8080 with model profiles.
set -Eeuo pipefail

# -------- defaults --------
: "${PORT:=8080}"
: "${LLAMA_BIN:=$HOME/llama.cpp/build/bin/llama-server}"   # override if different
: "${WORK_DIR:=work}"
: "${PID_DIR:=$WORK_DIR/pids}"
: "${LOG_DIR:=$WORK_DIR/logs}"
: "${PROFILES_DIR:=profiles}"

mkdir -p "$PID_DIR" "$LOG_DIR"

PID_FILE="$PID_DIR/llama_server.pid"
LATEST_LINK="$LOG_DIR/latest_llm.log"

# -------- helpers --------
die(){ echo "err: $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }
port_busy(){ lsof -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | head -n1 || true; }
alive(){ [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; }

ping_llm(){
  curl -sS -m 2 -H 'Content-Type: application/json' \
    -d '{"model":"ping","messages":[{"role":"user","content":"ping"}],"max_tokens":4}' \
    "http://127.0.0.1:$PORT/v1/chat/completions" >/dev/null
}

wait_for_health(){
  local tries="${1:-40}"
  while (( tries-- > 0 )); do
    if ping_llm; then return 0; fi
    sleep 0.3
  done
  return 1
}

wait_for_vram(){
  # If nvidia-smi exists, wait for free VRAM >= MIN_FREE_MB
  local need="${1:-0}"
  if ! have nvidia-smi || [[ "$need" -le 0 ]]; then return 0; fi
  local tries=100
  while (( tries-- > 0 )); do
    local free
    free="$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits 2>/dev/null | head -n1 || echo 0)"
    [[ "${free:-0}" -ge "$need" ]] && return 0
    sleep 0.3
  done
  return 0
}

start_profile(){
  local profile="$1"
  [[ -f "$PROFILES_DIR/$profile.env" ]] || die "profile not found: $PROFILES_DIR/$profile.env"
  # shellcheck disable=SC1090
  source "$PROFILES_DIR/$profile.env"

  [[ -r "${MODEL_PATH:-}" ]] || die "MODEL_PATH missing/unreadable in $profile.env"
  [[ -x "$LLAMA_BIN" ]] || die "llama-server not found/executable: $LLAMA_BIN"

  # stop any existing instance first
  stop_silent

  # ensure VRAM
  wait_for_vram "${MIN_FREE_MB:-0}"

  local stamp; stamp="$(date +%Y%m%d-%H%M%S)"
  local log="$LOG_DIR/llm.${profile}.${stamp}.log"

  # build server command
  # Common safe defaults + profile overrides
  local args=(
    -m "$MODEL_PATH"
    --port "$PORT"
    -c "${CONTEXT:-4096}"
    --batch-size "${BATCH_SIZE:-64}"
    -ngl "${NGL:-60}"
    -t "${THREADS:-12}"
    --jinja
    --no-warmup
  )
  [[ -n "${MAIN_GPU:-}"   ]] && args+=( --main-gpu "$MAIN_GPU" )
  [[ -n "${SPLIT_MODE:-}" ]] && args+=( --split-mode "$SPLIT_MODE" )
  [[ -n "${EXTRA_ARGS:-}" ]] && eval "args+=($EXTRA_ARGS)"

  echo "[llmctl] starting $profile on :$PORT → $log"
  # start detached
  ( nohup "$LLAMA_BIN" "${args[@]}" >"$log" 2>&1 & echo $! >"$PID_FILE" ) || die "failed to start llama-server"
  ln -sfn "$(basename "$log")" "$LATEST_LINK"

  # wait for http health
  if ! wait_for_health 60; then
    echo "warn: server did not respond on port $PORT; see log: $log" >&2
    exit 1
  fi

  # Optional: write env exports to reuse in pipeline
  {
    echo "export LLM_ENDPOINT=http://127.0.0.1:$PORT/v1/chat/completions"
    echo "export LLM_MODEL=$(basename "$MODEL_PATH")"
  } > "$WORK_DIR/llm.env"

  echo "[llmctl] up: pid $(cat "$PID_FILE"), model $(basename "$MODEL_PATH")"
}

stop_silent(){
  local pid=""
  if [[ -f "$PID_FILE" ]]; then pid="$(cat "$PID_FILE" 2>/dev/null || true)"; fi
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "[llmctl] stopping pid $pid"
    kill "$pid" 2>/dev/null || true
    for _ in {1..40}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"

  # if port still held, try lsof
  local holder; holder="$(port_busy || true)"
  if [[ -n "$holder" ]]; then
    echo "[llmctl] port $PORT still busy (pid $holder), killing"
    kill "$holder" 2>/dev/null || true
    sleep 0.2
    kill -9 "$holder" 2>/dev/null || true
  fi
}

stop_cmd(){ stop_silent; echo "[llmctl] down"; }

status_cmd(){
  if alive; then
    local pid; pid="$(cat "$PID_FILE")"
    echo "[llmctl] up: pid $pid, port $PORT"
  else
    echo "[llmctl] down"
  fi
}

switch_cmd(){
  local profile="$1"
  stop_silent
  start_profile "$profile"
}

env_cmd(){
  local profile="$1"
  [[ -f "$PROFILES_DIR/$profile.env" ]] || die "profile not found: $PROFILES_DIR/$profile.env"
  # shellcheck disable=SC1090
  source "$PROFILES_DIR/$profile.env"
  echo "export LLM_ENDPOINT=http://127.0.0.1:$PORT/v1/chat/completions"
  echo "export LLM_MODEL=$(basename "$MODEL_PATH")"
}

usage(){
  cat <<EOF
llmctl: start/stop/switch llama-server (single port: $PORT)
Usage:
  scripts/llm/llmctl.sh start <qwen14|llm4d>
  scripts/llm/llmctl.sh stop
  scripts/llm/llmctl.sh switch <qwen14|llm4d>
  scripts/llm/llmctl.sh status
  scripts/llm/llmctl.sh env <qwen14|llm4d>   # prints export lines you can eval
Profiles dir: $PROFILES_DIR
EOF
}

cmd="${1:-}"; shift || true
case "$cmd" in
  start)   start_profile "${1:-}";;
  stop)    stop_cmd;;
  switch)  switch_cmd "${1:-}";;
  status)  status_cmd;;
  env)     env_cmd "${1:-}";;
  *)       usage; exit 1;;
esac

