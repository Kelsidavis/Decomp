#!/usr/bin/env python3
# tools/function_hunt/label.py
from __future__ import annotations

import os, re, json, time, random
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# -------------------- env & defaults --------------------
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")

MAX_TOKENS = int(os.getenv("HUNT_LLM_MAX_TOKENS", "256"))
CONCURRENCY = max(1, int(os.getenv("HUNT_LLM_CONCURRENCY", "4")))
TIMEOUT_S = int(os.getenv("HUNT_LLM_TIMEOUT", "60"))
RETRIES = int(os.getenv("HUNT_LLM_RETRIES", "2"))

# prefer grammar? (off by default for llama.cpp OpenAI mode)
PREFER_GRAMMAR = os.getenv("HUNT_GRAMMAR", "0").lower() in ("1", "true", "yes", "on")
# force text mode (do not send response_format={"type":"json_object"})
FORCE_TEXT = os.getenv("HUNT_LLM_FORCE_TEXT", "0").lower() in ("1", "true", "yes", "on")

# print a line per function?
VERBOSE_PER_FUNC = os.getenv("HUNT_LLM_VERBOSE", "0").lower() in ("1", "true", "yes", "on")

# prompt constraints
PROMPT = """You are a reverse-engineering assistant. Given evidence about ONE function,
infer what it likely does. Return STRICT JSON ONLY with keys exactly:
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

# -------------------- helpers --------------------
def _extract_content(api_json: Dict[str, Any]) -> str:
    """Extract 'content' from OpenAI-compatible response variants."""
    choices = api_json.get("choices") or []
    if not choices:
        return ""
    msg = choices[0].get("message") or {}
    content = (msg.get("content") or "").strip()
    if content:
        return content
    # some servers put text under 'reasoning_content' (llama.cpp sometimes leaks)
    rc = (msg.get("reasoning_content") or "").strip()
    if rc:
        return rc
    # other fallbacks
    return (choices[0].get("text") or "").strip()

def _extract_balanced_json(text: str) -> str | None:
    """Return first balanced {...} JSON object substring, if any."""
    start = None
    depth = 0
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    return text[start:i+1]
    return None

def _strip_code_fences(s: str) -> str:
    """Remove ```...``` fences (optionally ```json)."""
    s = s.strip()
    if s.startswith("```"):
        # remove first fence
        s = s.split("```", 1)[-1]
        # remove trailing fence if present
        if "```" in s:
            s = s.rsplit("```", 1)[0]
    return s.strip()

def _safe_json_loads(text: str) -> Dict[str, Any] | None:
    """Best-effort JSON parse with multiple fallbacks."""
    if not text:
        return None
    # direct
    try:
        return json.loads(text)
    except Exception:
        pass
    # code fences
    try:
        cf = _strip_code_fences(text)
        if cf and cf != text:
            return json.loads(cf)
    except Exception:
        pass
    # find first balanced {...}
    try:
        bal = _extract_balanced_json(text)
        if bal:
            return json.loads(bal)
    except Exception:
        pass
    return None

def _coerce_label(o: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure types & fields are normalized."""
    name = o.get("name", "unknown")
    o["name"] = str(name)[:128] if name is not None else "unknown"

    def _as_list(v):
        if v is None: return []
        if isinstance(v, list): return [str(x)[:256] for x in v]
        return [str(v)[:256]]

    o["tags"] = _as_list(o.get("tags"))
    o["inputs"] = _as_list(o.get("inputs"))
    o["outputs"] = _as_list(o.get("outputs"))
    o["side_effects"] = _as_list(o.get("side_effects"))
    ev = o.get("evidence")
    if isinstance(ev, list):
        o["evidence"] = [str(x)[:512] for x in ev]
    elif ev is None:
        o["evidence"] = []
    else:
        o["evidence"] = [str(ev)[:512]]

    try:
        o["confidence"] = float(o.get("confidence", 0.5))
    except Exception:
        o["confidence"] = 0.5

    return o

def _trim_evidence(func: Dict[str, Any]) -> Dict[str, Any]:
    """Build prompt inputs from a function record."""
    imports = ", ".join([str(x) for x in (func.get("imports") or [])][:24])
    # drop noisy PE header string
    strings_src = [s for s in (func.get("strings") or []) if "This program cannot be run in DOS mode" not in str(s)]
    strings = ", ".join([str(x) for x in strings_src[:24]])
    snippet = (func.get("snippet") or "")[:1000]
    signals = json.dumps(func.get("signals", {}))[:800]
    return {
        "imports": imports,
        "strings": strings,
        "snippet": snippet,
        "signals": signals,
    }

def _one_payload(f: Dict[str, Any], model: str, use_grammar: bool, use_respfmt: bool) -> Dict[str, Any]:
    ev = _trim_evidence(f)
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return ONLY valid JSON. Do NOT include chain-of-thought."},
            {"role": "user", "content": PROMPT.format(**ev)},
        ],
        "temperature": 0.2,
        "max_tokens": MAX_TOKENS,
    }
    # Prefer structured JSON when server supports it
    if use_respfmt:
        payload["response_format"] = {"type": "json_object"}
    # grammar (GBNF) is OFF by default; only send if explicitly requested
    if use_grammar:
        payload["grammar"] = r'''
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
    return payload

# -------------------- LLM core --------------------
def _call_llm(sess: requests.Session, endpoint: str, model: str, f: Dict[str, Any]) -> Dict[str, Any]:
    """Call LLM for one function with fallbacks. Always returns a normalized record."""
    # Compose fallbacks
    use_grammar = PREFER_GRAMMAR
    use_respfmt = not FORCE_TEXT

    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            payload = _one_payload(f, model, use_grammar, use_respfmt)
            r = sess.post(endpoint, json=payload, timeout=TIMEOUT_S)
            if not r.ok:
                body_lower = (r.text or "").lower()
                msg = f"{r.status_code} {r.reason}"
                # If server rejects grammar, disable and retry
                if (r.status_code in (400, 422)) and "grammar" in body_lower and use_grammar:
                    print("[llm] disabling grammar and retrying…", flush=True)
                    use_grammar = False
                    continue
                # If server rejects response_format, drop it and retry
                if (r.status_code in (400, 422)) and "response_format" in body_lower and use_respfmt:
                    print("[llm] disabling response_format and retrying…", flush=True)
                    use_respfmt = False
                    continue
                r.raise_for_status()

            data = r.json()
            txt = _extract_content(data)
            obj = _safe_json_loads(txt)
            if obj is None:
                obj = {
                    "name": f.get("name", "unknown"),
                    "tags": [],
                    "inputs": [],
                    "outputs": [],
                    "side_effects": [],
                    "confidence": 0.3,
                    "evidence": [f"invalid JSON from model (first 160): {txt[:160]}"],
                }
            obj = _coerce_label(obj)
            # carry address/original
            obj["_addr"] = f.get("address")
            obj["_orig_name"] = f.get("name")
            return obj

        except Exception as e:
            last_err = e
            time.sleep(0.8 * (attempt + 1) + random.uniform(0, 0.4))

    # All attempts failed → minimal record
    return _coerce_label({
        "name": f.get("name", "unknown"),
        "tags": [],
        "inputs": [],
        "outputs": [],
        "side_effects": [],
        "confidence": 0.3,
        "evidence": [f"llm error: {str(last_err)[:160]}"],
        "_addr": f.get("address"),
        "_orig_name": f.get("name"),
    })

# -------------------- public API --------------------
def llm_label_batch(funcs: List[Dict[str, Any]], endpoint: str | None, model: str | None) -> List[Dict[str, Any]]:
    """Label a batch of functions with the LLM (or fall back with low-confidence)."""
    funcs = funcs or []
    if not endpoint or not model:
        # Offline fallback
        out = []
        for f in funcs:
            out.append(_coerce_label({
                "name": f.get("name", "unknown"),
                "tags": [], "inputs": [], "outputs": [], "side_effects": [],
                "confidence": 0.3, "evidence": ["no_llm_configured"],
                "_addr": f.get("address"), "_orig_name": f.get("name"),
            }))
        return out

    sess = requests.Session()
    out: List[Dict[str, Any]] = [None] * len(funcs)  # type: ignore
    total = len(funcs)
    every = max(5, total // 20)  # ~5% steps, min every 5

    def do_one(idx_f):
        i, f = idx_f
        if VERBOSE_PER_FUNC:
            nm = f.get("name") or f.get("address") or "sub_unknown"
            print(f"[llm] labeling {nm}", flush=True)
        return i, _call_llm(sess, endpoint, model, f)

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futs = {ex.submit(do_one, (i, f)): i for i, f in enumerate(funcs)}
        for k, fut in enumerate(as_completed(futs), 1):
            i, rec = fut.result()
            out[i] = rec
            if (k % every == 0) or (k == total):
                print(f"[llm] progress {k}/{total}", flush=True)

    # fill any rare gaps (shouldn't happen)
    for i in range(len(out)):
        if out[i] is None:
            f = funcs[i]
            out[i] = _coerce_label({
                "name": f.get("name", "unknown"),
                "tags": [], "inputs": [], "outputs": [], "side_effects": [],
                "confidence": 0.3, "evidence": ["internal_error_fill"],
                "_addr": f.get("address"), "_orig_name": f.get("name"),
            })

    return out  # type: ignore

# -------------------- cli (manual test) --------------------
if __name__ == "__main__":
    import sys
    # Simple sanity: expects a single JSONL file of functions on stdin or path arg
    # Outputs labeled JSONL to stdout
    def load_funcs(path: str | None):
        items = []
        fh = open(path, "r", encoding="utf-8") if path else sys.stdin
        for ln in fh:
            ln = ln.strip()
            if not ln: continue
            try:
                items.append(json.loads(ln))
            except Exception:
                pass
        if path: fh.close()
        return items

    path = sys.argv[1] if len(sys.argv) > 1 else None
    funcs = load_funcs(path)
    labeled = llm_label_batch(funcs, LLM_ENDPOINT, LLM_MODEL)
    for rec in labeled:
        print(json.dumps(rec, ensure_ascii=False))

