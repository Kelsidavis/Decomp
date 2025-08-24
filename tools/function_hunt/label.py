#!/usr/bin/env python3
# tools/function_hunt/label.py — concurrent labeling with grammar fallback (llama.cpp-friendly)

from __future__ import annotations
import json, os, re, time
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

PROMPT = """You are a reverse-engineering assistant. Given evidence about a function,
infer what it likely does.

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

# A minimal JSON grammar. Some llama.cpp builds reject 'grammar', so we auto-fallback.
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

def _extract_content(api_json: Dict[str, Any]) -> str:
    ch = (api_json.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    content = (msg.get("content") or "").strip()
    if content:
        return content
    rc = (msg.get("reasoning_content") or "").strip()
    if rc:
        m = re.findall(r'(\{.*\})', rc, flags=re.DOTALL)
        if m: return m[-1].strip()
        return rc
    t = ch.get("text") or (ch.get("delta") or {}).get("content") or ""
    return (t or "").strip()

def _one_payload(f: Dict[str, Any], model: str, use_grammar: bool) -> Dict[str, Any]:
    # Trim noisy evidence
    imports = ", ".join(f.get("imports", [])[:24])
    strings = ", ".join([s for s in f.get("strings", []) if s and "This program cannot be run in DOS mode" not in s][:24])
    snippet = (f.get("snippet") or "")[:1000]
    signals = json.dumps(f.get("signals", {}))[:800]

    payload = {
        "model": model,
        "messages": [
            {"role": "system",
             "content": "Return the final answer ONLY as valid JSON. Do NOT include chain-of-thought."},
            {"role": "user",
             "content": PROMPT.format(imports=imports, strings=strings, snippet=snippet, signals=signals)}
        ],
        "temperature": 0.2,
        "max_tokens": int(os.getenv("HUNT_LLM_MAX_TOKENS", "256")),
        "response_format": {"type": "text"},
    }
    if use_grammar:
        payload["grammar"] = GBNF_JSON
    else:
        # Prefer structured JSON if server supports it (llama.cpp does for many builds)
        if os.getenv("HUNT_LLM_FORCE_TEXT", "") not in ("1","true","True"):
            payload["response_format"] = {"type": "json_object"}
    return payload

def llm_label_batch(funcs: List[Dict[str, Any]], endpoint: str, model: str) -> List[Dict[str, Any]]:
    labeled: List[Dict[str, Any]] = []
    if not (endpoint and model):
        for f in funcs:
            labeled.append({
                "name": f.get("name","unknown"),
                "tags": [], "inputs": [], "outputs": [], "side_effects": [],
                "confidence": 0.3, "evidence": ["no_llm"],
                "_addr": f.get("address"), "_orig_name": f.get("name")
            })
        return labeled

    conc = max(1, int(os.getenv("HUNT_LLM_CONCURRENCY", "4")))
    timeout_s = int(os.getenv("HUNT_LLM_TIMEOUT", "60"))
    retries = int(os.getenv("HUNT_LLM_RETRIES", "2"))
    prefer_grammar = os.getenv("HUNT_GRAMMAR", "0") in ("1","true","True","yes","on")

    sess = requests.Session()

    def do_one(f: Dict[str, Any]) -> Dict[str, Any]:
        use_grammar = prefer_grammar
        last_err = None

        for attempt in range(retries + 1):
            try:
                r = sess.post(endpoint, json=_one_payload(f, model, use_grammar), timeout=timeout_s)
                if not r.ok:
                    msg = f"{r.status_code} {r.text[:200]}"
                    # If grammar rejected, retry once without grammar
                    if ("400" in msg or "422" in msg) and "grammar" in r.text.lower() and use_grammar:
                        print("[llm] disabling grammar and retrying this request…", flush=True)
                        use_grammar = False
                        continue
                    r.raise_for_status()
                data = r.json()
                txt = _extract_content(data)
                obj = json.loads(txt)
                # Normalize
                obj.setdefault("name", f.get("name","unknown"))
                obj.setdefault("tags", [])
                obj.setdefault("inputs", [])
                obj.setdefault("outputs", [])
                obj.setdefault("side_effects", [])
                obj.setdefault("confidence", 0.5)
                obj.setdefault("evidence", [])
                obj["_addr"] = f.get("address")
                obj["_orig_name"] = f.get("name")
                return obj
            except Exception as e:
                last_err = e
                time.sleep(0.8 * (attempt + 1))

        return {
            "name": f.get("name","unknown"),
            "tags": [], "inputs": [], "outputs": [], "side_effects": [],
            "confidence": 0.3, "evidence": ["no_llm_or_parse_error", str(last_err)[:120]],
            "_addr": f.get("address"), "_orig_name": f.get("name")
        }

    out: List[Dict[str, Any]] = [None] * len(funcs)
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = {ex.submit(do_one, f): i for i, f in enumerate(funcs)}
        for k, fut in enumerate(as_completed(futs), 1):
            i = futs[fut]
            try:
                out[i] = fut.result()
            except Exception as e:
                f = funcs[i]
                out[i] = {
                    "name": f.get("name","unknown"),
                    "tags": [], "inputs": [], "outputs": [], "side_effects": [],
                    "confidence": 0.3, "evidence": ["exception", str(e)[:120]],
                    "_addr": f.get("address"), "_orig_name": f.get("name")
                }
            if k % 25 == 0:
                print(f"[llm] progress {k}/{len(funcs)}", flush=True)

    return out

