#!/usr/bin/env python3
# tools/function_hunt/label.py — concurrent labeling with graceful grammar fallback

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

# A simple JSON grammar that many llama.cpp builds accept; some builds do not.
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
    # some llama.cpp builds put text in reasoning_content
    rc = (msg.get("reasoning_content") or "").strip()
    if rc:
        m = re.findall(r'(\{.*\})', rc, flags=re.DOTALL)
        if m: return m[-1].strip()
        return rc
    # legacy
    t = ch.get("text") or (ch.get("delta") or {}).get("content") or ""
    return t.strip()

def _one_payload(f: Dict[str, Any], model: str, use_grammar: bool) -> Dict[str, Any]:
    msg = PROMPT.format(
        imports=", ".join(f.get("imports", [])[:20]),
        strings=", ".join(f.get("strings", [])[:20]),
        snippet=(f.get("snippet") or "")[:1000],
        signals=json.dumps(f.get("signals", {}))[:800],
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system",
             "content": "Return the final answer ONLY as valid JSON. Do NOT include chain-of-thought."},
            {"role": "user", "content": msg}
        ],
        "temperature": 0.2,
        "max_tokens": int(os.getenv("HUNT_LLM_MAX_TOKENS", "256")),
        "response_format": {"type": "text"},
    }
    if use_grammar:
        payload["grammar"] = GBNF_JSON
    else:
        # many llama.cpp builds support this and it’s safer than free-form
        if os.getenv("HUNT_LLM_FORCE_TEXT", "") not in ("1","true","True"):
            payload["response_format"] = {"type": "json_object"}
    return payload

def llm_label_batch(funcs: List[Dict[str, Any]], endpoint: str, model: str) -> List[Dict[str, Any]]:
    labeled: List[Dict[str, Any]] = []
    if not (endpoint and model):
        # fast fallback
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
    no_grammar_env = os.getenv("HUNT_LLM_NO_GRAMMAR", "")
    prefer_grammar = not (no_grammar_env in ("1","true","True","yes","on"))

    sess = requests.Session()

    def do_one(f: Dict[str, Any]) -> Dict[str, Any]:
        def request_once(use_grammar: bool):
            payload = _one_payload(f, model, use_grammar)
            r = sess.post(endpoint, json=payload, timeout=timeout_s)
            if not r.ok:
                # Pass the server body upward for inspection
                raise requests.HTTPError(f"{r.status_code} {r.text[:200]}")
            return r.json()

        # Try up to (retries+1) attempts; if grammar is enabled and server says grammar bad,
        # retry immediately once WITHOUT grammar, then continue normal retries.
        use_grammar = prefer_grammar
        last_err = None
        tried_without_grammar = False

        for attempt in range(retries + 1):
            try:
                data = request_once(use_grammar)
                txt = _extract_content(data)
                obj = json.loads(txt)
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
            except requests.HTTPError as he:
                s = str(he)
                print(f"[llm] HTTP error: {s}", flush=True)
                if ("400" in s or "422" in s) and "grammar" in s.lower() and use_grammar:
                    # Turn off grammar and retry immediately
                    print("[llm] disabling grammar and retrying for this request…", flush=True)
                    use_grammar = False
                    tried_without_grammar = True
                    continue
                last_err = he
            except Exception as e:
                last_err = e
            time.sleep(0.8 * (attempt + 1))

        # final fallback
        return {
            "name": f.get("name","unknown"),
            "tags": [], "inputs": [], "outputs": [], "side_effects": [],
            "confidence": 0.3,
            "evidence": ["no_llm_or_parse_error", str(last_err)[:120]],
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

