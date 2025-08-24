#!/usr/bin/env bash
export LLM_ENDPOINT=${LLM_ENDPOINT:-http://127.0.0.1:8080/v1/chat/completions}
export LLM_MODEL=${LLM_MODEL:-Qwen3-14B-UD-Q5_K_XL.gguf}
set -euo pipefail

# LLM config (set in env or edit here)
: "${LLM_ENDPOINT:=http://localhost:8080}"
: "${LLM_MODEL:=qwen3-14b-q5}"

# Optional enrichment toggles (requires capa/yara/radare2 installed)
export HUNT_CAPA=1
export HUNT_YARA=1

# Auto-discover binary + *_out.json under work/ and run hunt
python3 tools/function_hunt/run_autodiscover.py

