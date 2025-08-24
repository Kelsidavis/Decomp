#!/usr/bin/env python3
# tools/function_hunt/label.py
# LLM-assisted labeling for reverse-engineering “Function Hunt”.
# - Works with OpenAI-compatible chat endpoints (e.g., llama.cpp server)
# - Robust to responses that put text in `reasoning_content` instead of `message.content`
# - Prompts for STRICT JSON and (optionally) constrains output via a JSON grammar
# - Falls back to safe defaults if the call/parsing fails

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

import requests


# =========================
# Prompt & JSON Constraints
# =========================

PROMPT = """You are a reverse-engineering assistant. Given evidence, infer what the function likely does.

Output STRICT JSON with keys exactly:
- name (string)
- tags (array of strings)
- inputs (array of strings)
- outputs (array of strings)
- side_effects (array of strings)
- confidence (number 0..1)
- evidence (array of strings)

Return ONLY the JSON, no commentary.

EVIDENCE:
Imports: {imports}
Strings: {strings}
DecompiledSnippet:
{snippet}
Signals: {signals}
"""

# A permissive JSON grammar for llama.cpp (ignored by servers that don't support it).
GBNF_JSON = r'''
root           ::= object
object         ::= "{" ws members? ws "}"
members        ::= pair ( ws "," ws pair )*
pair           ::= string ws ":" ws value
array          ::= "[" ws elements? ws "]"
elements       ::= value ( ws "," ws value )*
value          ::= string | number | object | array | "true" | "false" | "null"
string         ::= "\"" chars "\""
chars          ::= char*
char           ::= [^"\\\u0000-\u001F] | "\\" ( ["\\/bfnrt] | "u" hex hex hex hex )
hex            ::= [0-9a-fA-F]
number         ::= "-"? int frac? exp?
int            ::= "0" | [1-9][0-9]*
frac           ::= "." [0-9]+
exp            ::= [eE] [+\-]? [0-9]+
ws             ::= [ \t\n\r]* 
'''


# =====================
# Response Text Extract
# =====================

def _extract_content(api_json: Dict[str, Any]) -> str:
    """
    Prefer message.content. If empty, try message.reasoning_content.
    As a last resort, extract the last {...} or [...] JSON-looking block from
    either field. Also accept some legacy shapes (choice.text).
    """
    choices = api_json.get("choices") or []
    ch0 = choices[0] if choices else {}
    msg = ch0.get("message") or {}
    content = (msg.get("content") or "").strip()
    reasoning = (msg.get("reasoning_content") or "").strip()

    if content:
        return content

    # Some servers (llama.cpp) put the answer in reasoning_content
    if reasoning:
        # If reasoning contains a JSON block, take the last one.
        for pattern in (r'(\{.*\})', r'(\[.*\])'):
            mm = list(re.finditer(pattern, reasoning, flags=re.DOTALL))
            if mm:
                return mm[-1].group(1).strip()
        return reasoning

    # Legacy fallbacks
    legacy = ch0.get("text") or (ch0.get("delta") or {}).get("content") or ""
    return legacy.strip()


# ================
# HTTP + Retries
# ================

def _chat_request(endpoint: str, payload: Dict[str, Any], timeout_s: int = 60, retries: int = 2) -> Dict[str, Any]:
    last_err = None
    for attempt in range(retries + 1):
        try:
            r = requests.post(endpoint, json=payload, timeout=timeout_s)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last_err = e
            # Backoff (simple)
            time.sleep(0.6 * (attempt + 1))
    raise last_err  # type: ignore[misc]


# =========================
# Public API: label batch
# =========================

def llm_label_batch(funcs: List[Dict[str, Any]], endpoint: str, model: str) -> List[Dict[str, Any]]:
    """
    Label a list of function dicts using an OpenAI-compatible chat endpoint.
    Each returned item includes:
      - name / tags / inputs / outputs / side_effects / confidence / evidence
      - _addr / _orig_name (for traceability)
    """
    labeled: List[Dict[str, Any]] = []
    use_llm = bool(endpoint and model)

    for f in funcs:
        print(f"[llm] labeling {f.get('name')} @ {f.get('address')}", flush=True)
        if use_llm:
            msg = PROMPT.format(
                imports=", ".join(f.get("imports", [])[:20]),
                strings=", ".join(f.get("strings", [])[:20]),
                snippet=(f.get("snippet") or "")[:1000],
                signals=json.dumps(f.get("signals", {}))[:800],
            )
            payload = {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "Return the final answer ONLY as valid JSON. Do NOT include chain-of-thought or reasoning."
                    },
                    {"role": "user", "content": msg}
                ],
                "temperature": 0.2,
                "max_tokens": 512,
                # Nudge servers to put answer into message.content:
                "response_format": {"type": "text"},
                # If llama.cpp supports `grammar`, this constrains output to JSON.
                "grammar": GBNF_JSON,
            }
            try:
                data = _chat_request(endpoint, payload, timeout_s=90, retries=2)
                txt = _extract_content(data)
                lab = json.loads(txt)  # parse STRICT JSON
                # minimal validation / coercion
                lab.setdefault("name", f.get("name", "unknown"))
                lab.setdefault("tags", [])
                lab.setdefault("inputs", [])
                lab.setdefault("outputs", [])
                lab.setdefault("side_effects", [])
                lab.setdefault("confidence", 0.5)
                lab.setdefault("evidence", [])
            except Exception:
                # Graceful fallback
                lab = {
                    "name": f.get("name", "unknown"),
                    "tags": [],
                    "inputs": [],
                    "outputs": [],
                    "side_effects": [],
                    "confidence": 0.3,
                    "evidence": ["no_llm_or_parse_error"],
                }
        else:
            # No endpoint/model → deterministic fallback
            lab = {
                "name": f.get("name", "unknown"),
                "tags": [],
                "inputs": [],
                "outputs": [],
                "side_effects": [],
                "confidence": 0.3,
                "evidence": ["no_llm"],
            }

        # Traceability
        lab["_addr"] = f.get("address")
        lab["_orig_name"] = f.get("name")

        labeled.append(lab)

    return labeled

