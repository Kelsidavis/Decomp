#!/usr/bin/env python3
# tools/function_hunt/label.py
from __future__ import annotations

import os, re, json, time, random, hashlib, pathlib
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "")
LLM_MODEL    = os.getenv("LLM_MODEL", "")

MAX_TOKENS  = int(os.getenv("HUNT_LLM_MAX_TOKENS", "256"))
CONCURRENCY = max(1, int(os.getenv("HUNT_LLM_CONCURRENCY", "6")))
TIMEOUT_S   = int(os.getenv("HUNT_LLM_TIMEOUT", "60"))
RETRIES     = int(os.getenv("HUNT_LLM_RETRIES", "2"))

PREFER_GRAMMAR = os.getenv("HUNT_GRAMMAR", "0").lower() in ("1","true","yes","on")
FORCE_TEXT     = os.getenv("HUNT_LLM_FORCE_TEXT", "0").lower() in ("1","true","yes","on")

USE_CACHE = os.getenv("HUNT_CACHE", "0").lower() in ("1","true","yes","on")
CACHE_DIR = pathlib.Path(os.getenv("HUNT_CACHE_DIR", "work/cache/labels"))
if os.getenv("HUNT_CACHE_CLEAR", "0").lower() in ("1","true","yes","on"):
    if CACHE_DIR.exists():
        for p in CACHE_DIR.glob("*.json"):
            try: p.unlink()
            except Exception: pass

VERBOSE_PER_FUNC = os.getenv("HUNT_LLM_VERBOSE", "0").lower() in ("1","true","yes","on")

PROMPT = """You are a reverse-engineering assistant.
Given evidence about ONE function, infer what it does and return STRICT JSON ONLY with keys:
- name (string)
- tags (array of strings)
- inputs (array of strings)
- outputs (array of strings)
- side_effects (array of strings)
- confidence (number 0..1)
- evidence (array of strings)

Style guidance:
- Use descriptive, conventional names; consider module/file/subsystem context.
- Derive pre/postconditions implicitly via inputs/outputs & side_effects.
- If evidence suggests standard APIs (memcpy, crc32, Win32 handle ops), tag accordingly.

RICH EVIDENCE:
Module: {module}
Address: {addr}
Size: {size}
Callers: {callers}
Callees: {callees}
IAT (grouped): {iat_by_dll}
String xrefs: {string_xrefs}
FLOSS strings: {floss_strings}
CAPA hits: {capa_hits}
YARA hits: {yara_hits}

DecompiledSnippet (windowed):
{snippet}
"""

def _extract_content(api_json: Dict[str, Any]) -> str:
    ch = (api_json.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    txt = (msg.get("content") or "").strip()
    if txt: return txt
    rc = (msg.get("reasoning_content") or "").strip()
    if rc: return rc
    return (ch.get("text") or "").strip()

def _strip_code_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = s.split("```", 1)[-1]
        if "```" in s:
            s = s.rsplit("```", 1)[0]
    return s.strip()

def _extract_balanced_json(text: str) -> Optional[str]:
    start = None
    depth = 0
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0: start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    return text[start:i+1]
    return None

def _safe_json_loads(text: str) -> Optional[Dict[str, Any]]:
    if not text: return None
    try: return json.loads(text)
    except Exception: pass
    try:
        cf = _strip_code_fences(text)
        if cf and cf != text:
            return json.loads(cf)
    except Exception: pass
    try:
        bal = _extract_balanced_json(text)
        if bal: return json.loads(bal)
    except Exception: pass
    return None

def _coerce_label(o: Dict[str, Any]) -> Dict[str, Any]:
    name = o.get("name", "unknown")
    o["name"] = str(name)[:128] if name is not None else "unknown"

    def _as_list(v):
        if v is None: return []
        if isinstance(v, list): return [str(x)[:256] for x in v]
        return [str(v)[:256]]

    o["tags"]         = _as_list(o.get("tags"))
    o["inputs"]       = _as_list(o.get("inputs"))
    o["outputs"]      = _as_list(o.get("outputs"))
    o["side_effects"] = _as_list(o.get("side_effects"))

    ev = o.get("evidence")
    if isinstance(ev, list):   o["evidence"] = [str(x)[:512] for x in ev]
    elif ev is None:           o["evidence"] = []
    else:                      o["evidence"] = [str(ev)[:512]]

    try: o["confidence"] = float(o.get("confidence", 0.5))
    except Exception: o["confidence"] = 0.5
    return o

def _short_list(xs, n=12):
    xs = list(xs or [])
    return xs[:n] + (["…"] if len(xs) > n else [])

def _window_lines(s: str, min_lines: int, max_lines: int, max_chars: int) -> str:
    if not s: return s
    lines = s.splitlines()
    n = min(max(len(lines), min_lines), max_lines)
    w = "\n".join(lines[:n])
    if len(w) > max_chars:
        w = w[:max_chars]
    return w

def _trim_evidence(func: Dict[str, Any]) -> Dict[str, Any]:
    max_chars  = int(os.getenv("MAX_PROMPT_CHARS", "6000"))
    max_lines  = int(os.getenv("MAX_PROMPT_LINES", "80"))
    min_lines  = int(os.getenv("MIN_PROMPT_LINES", "50"))

    sig   = func.get("signals") or {}
    mod   = sig.get("module") or ""
    iat   = sig.get("iat_by_dll") or {}
    xrefs = sig.get("string_xrefs") or []
    capa  = sig.get("capa_hits") or []
    yara  = sig.get("yara_hits") or []
    floss = sig.get("floss_strings") or []

    callers = _short_list(sig.get("callers") or [])
    callees = _short_list(sig.get("callees") or [])

    snippet_raw = (func.get("snippet") or "")
    snippet = _window_lines(snippet_raw, min_lines, max_lines, max_chars)

    addr = func.get("address") or ""
    size = func.get("size") or 0

    return {
        "module": mod, "addr": addr, "size": size,
        "iat_by_dll": iat, "string_xrefs": _short_list(xrefs, 16),
        "floss_strings": _short_list(floss, 16),
        "capa_hits": _short_list([c.get("rule","") for c in capa], 12),
        "yara_hits": _short_list([y.get("rule","") for y in yara], 12),
        "callers": callers, "callees": callees,
        "snippet": snippet
    }

def _one_payload(f: Dict[str, Any], model: str, use_grammar: bool, use_respfmt: bool) -> Dict[str, Any]:
    ev = _trim_evidence(f)
    payload = {
        "model": model,
        "messages": [
            {"role": "system",
             "content": "Return ONLY valid JSON. No chain-of-thought. Keys must match the required schema exactly."},
            {"role": "user", "content": PROMPT.format(**ev)},
        ],
        "temperature": 0.2,
        "max_tokens": MAX_TOKENS,
    }
    if use_respfmt:
        payload["response_format"] = {"type": "json_object"}
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

def _cache_key(f: Dict[str, Any], model: Optional[str] = None) -> str:
    model = model or LLM_MODEL
    addr    = str(f.get("address") or f.get("addr") or f.get("ea") or f.get("name") or "")
    imports = ",".join([str(x) for x in (f.get("imports") or [])])
    strings = ",".join([str(x) for x in (f.get("strings") or [])])
    snippet = f.get("snippet") or ""
    content_hash = hashlib.sha1("\n".join([addr, imports, strings, snippet]).encode("utf-8","ignore")).hexdigest()
    prompt_hash  = hashlib.sha1(PROMPT.encode("utf-8","ignore")).hexdigest()[:12]
    salt = f"{model}|tok{MAX_TOKENS}|g{int(PREFER_GRAMMAR)}|t{int(FORCE_TEXT)}|p{prompt_hash}"
    return hashlib.sha1(f"{salt}|{content_hash}".encode("utf-8","ignore")).hexdigest()

def _cache_load(key: str) -> Optional[Dict[str, Any]]:
    if not USE_CACHE: return None
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = CACHE_DIR / f"{key}.json"
    if not p.exists(): return None
    try: return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception: return None

def _cache_save(key: str, obj: Dict[str, Any]) -> None:
    if not USE_CACHE: return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / f"{key}.json").write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    except Exception: pass

def _call_llm(sess: requests.Session, endpoint: str, model: str, f: Dict[str, Any]) -> Dict[str, Any]:
    use_grammar = PREFER_GRAMMAR
    use_respfmt = not FORCE_TEXT

    last_err: Optional[Exception] = None
    for attempt in range(RETRIES + 1):
        try:
            payload = _one_payload(f, model, use_grammar, use_respfmt)
            r = sess.post(endpoint, json=payload, timeout=TIMEOUT_S)
            if not r.ok:
                body_lower = (r.text or "").lower()
                if (r.status_code in (400,422)) and "grammar" in body_lower and use_grammar:
                    print("[llm] disabling grammar and retrying…", flush=True)
                    use_grammar = False
                    continue
                if (r.status_code in (400,422)) and "response_format" in body_lower and use_respfmt:
                    print("[llm] disabling response_format and retrying…", flush=True)
                    use_respfmt = False
                    continue
                r.raise_for_status()

            data = r.json()
            txt  = _extract_content(data)
            obj  = _safe_json_loads(txt)
            if obj is None:
                obj = {
                    "name": f.get("name","unknown"), "tags": [], "inputs": [], "outputs": [],
                    "side_effects": [], "confidence": 0.3,
                    "evidence": [f"invalid JSON from model (first 160): {txt[:160]}"],
                }
            obj = _coerce_label(obj)
            obj["_addr"]      = f.get("address")
            obj["_orig_name"] = f.get("name")
            return obj

        except Exception as e:
            last_err = e
            time.sleep(0.8 * (attempt + 1) + random.uniform(0, 0.4))

    return _coerce_label({
        "name": f.get("name","unknown"),
        "tags": [], "inputs": [], "outputs": [], "side_effects": [],
        "confidence": 0.3, "evidence": [f"llm error: {str(last_err)[:160]}"],
        "_addr": f.get("address"), "_orig_name": f.get("name"),
    })

def llm_label_one(func: Dict[str, Any], endpoint: Optional[str], model: Optional[str]) -> Dict[str, Any]:
    if not endpoint or not model:
        return _coerce_label({
            "name": func.get("name","unknown"),
            "tags": [], "inputs": [], "outputs": [], "side_effects": [],
            "confidence": 0.3, "evidence": ["no_llm_configured"],
            "_addr": func.get("address"), "_orig_name": func.get("name"),
        })
    key = _cache_key(func, model)
    hit = _cache_load(key)
    if hit is not None:
        return _coerce_label(hit)
    sess = requests.Session()
    rec  = _call_llm(sess, endpoint, model, func)
    _cache_save(key, rec)
    return rec

def llm_label_batch(funcs: List[Dict[str, Any]], endpoint: Optional[str], model: Optional[str]) -> List[Dict[str, Any]]:
    funcs = funcs or []
    total = len(funcs)
    if total == 0: return []

    every = max(5, total // 20)
    if not endpoint or not model:
        out = []
        for f in funcs:
            out.append(_coerce_label({
                "name": f.get("name","unknown"),
                "tags": [], "inputs": [], "outputs": [], "side_effects": [],
                "confidence": 0.3, "evidence": ["no_llm_configured"],
                "_addr": f.get("address"), "_orig_name": f.get("name"),
            }))
        return out

    sess = requests.Session()
    out: List[Optional[Dict[str, Any]]] = [None] * total

    def work(idx_f: Tuple[int, Dict[str, Any]]):
        i, f = idx_f
        if VERBOSE_PER_FUNC:
            nm = f.get("name") or f.get("address") or "sub_unknown"
            print(f"[llm] labeling {nm}", flush=True)
        key = _cache_key(f, model)
        cached = _cache_load(key)
        if cached is not None:
            return i, _coerce_label(cached)
        rec = _call_llm(sess, endpoint, model, f)
        _cache_save(key, rec)
        return i, rec

    done = 0
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futs = {ex.submit(work, (i, f)): i for i, f in enumerate(funcs)}
        for _f in as_completed(futs):
            i, rec = _f.result()
            out[i] = rec
            done += 1
            if (done % every == 0) or (done == total):
                print(f"[llm] progress {done}/{total}", flush=True)

    for i in range(len(out)):
        if out[i] is None:
            f = funcs[i]
            out[i] = _coerce_label({
                "name": f.get("name","unknown"),
                "tags": [], "inputs": [], "outputs": [], "side_effects": [],
                "confidence": 0.3, "evidence": ["internal_error_fill"],
                "_addr": f.get("address"), "_orig_name": f.get("name"),
            })
    return [x for x in out if x is not None]

if __name__ == "__main__":
    import sys
    def load_funcs(path: Optional[str]):
        items = []
        fh = open(path, "r", encoding="utf-8") if path else sys.stdin
        for ln in fh:
            ln = ln.strip()
            if not ln: continue
            try: items.append(json.loads(ln))
            except Exception: pass
        if path: fh.close()
        return items

    path = sys.argv[1] if len(sys.argv) > 1 else None
    funcs = load_funcs(path)
    labeled = llm_label_batch(funcs, LLM_ENDPOINT, LLM_MODEL)
    for rec in labeled:
        print(json.dumps(rec, ensure_ascii=False))

