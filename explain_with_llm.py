#!/usr/bin/env python3
import os, json, argparse, requests
from datetime import datetime

MODEL = os.getenv("LLM_MODEL", "qwen3coder30b")
ENDPOINT = os.getenv("LLM_ENDPOINT", "http://127.0.0.1:8080/v1/chat/completions")
MAX_FUNC_TOKENS = int(os.getenv("MAX_FUNC_TOKENS", "8000"))

SYSTEM_PROMPT = """You are a senior reverse engineer.
Given decompiled C (sometimes messy) and a bit of disassembly, do ALL of:
1) Summarize function behavior precisely (inputs, outputs, side effects).
2) Reconstruct a clean C/C++ prototype and a readable pseudocode version.
3) Identify library/API usage, switch tables, structs, constants.
4) Note obfuscation/packer/crypto hints and potential deobfuscation strategies.
5) List important cross-refs and how this function fits into a larger workflow.
Prefer correctness over speculation; if uncertain, say so concisely."""

USER_TEMPLATE = """Binary function report request.

Function: {name} @ {entry}
Signature: {sig}
Calling Convention: {cc}
Size (bytes): {size}
Stack Frame Size: {stack}

--- Decompiled C (chunk {chunk}/{total}) ---
{c}

--- Disassembly sample (selected) ---
{d}

Respond with:
- One-paragraph summary
- Clean prototype
- Pseudocode (succinct)
- Notable constants/strings/APIs
- Risks/assumptions/uncertainties
"""

def chat(messages, temperature=0.1, max_tokens=2048):
    payload = {
        "model": MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    r = requests.post(ENDPOINT, json=payload, timeout=600)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

def chunk_text(s, max_chars):
    if len(s) <= max_chars:
        return [s]
    return [s[i:i+max_chars] for i in range(0, len(s), max_chars)]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", help="out.json from Ghidra dump")
    ap.add_argument("--out", default="report.md")
    ap.add_argument("--max-chars", type=int, default=MAX_FUNC_TOKENS*4) # ~4 chars/token heuristic
    args = ap.parse_args()

    with open(args.jsonl) as f:
        lines = [json.loads(x) for x in f if x.strip()]
    # largest first
    lines.sort(key=lambda x: x.get("size_bytes", 0), reverse=True)

    sections = []
    for fn in lines:
        name = fn.get("function_name")
        entry = fn.get("entry")
        sig   = fn.get("sig")
        cc    = fn.get("calling_convention")
        size  = fn.get("size_bytes")
        stack = fn.get("stack_frame")
        ccode = fn.get("decompiled_c") or ""
        dis0  = "\n".join(fn.get("disasm_sample", [])[:60])

        c_chunks = chunk_text(ccode, args.max_chars)
        total = len(c_chunks) or 1
        fn_report = [f"## {name} ({entry})\n\n**Signature:** `{sig}` **CC:** `{cc}` **Size:** {size} bytes **Stack:** {stack}\n"]

        for idx, ck in enumerate(c_chunks, 1):
            user = USER_TEMPLATE.format(
                name=name, entry=entry, sig=sig, cc=cc, size=size, stack=stack,
                c=ck, d=dis0, chunk=idx, total=total
            )
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ]
            try:
                ans = chat(messages)
            except Exception as e:
                ans = f"_Error during analysis: {e}_"
            fn_report.append(ans.strip() + "\n")

        sections.append("\n".join(fn_report))

    header = f"# Automated Decompilation Report\n\nGenerated: {datetime.utcnow().isoformat()}Z\nFunctions analyzed: {len(lines)}\nModel: {MODEL}\nEndpoint: {ENDPOINT}\n\n---\n"
    with open(args.out, "w") as w:
        w.write(header + "\n\n".join(sections))

    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()

