#!/usr/bin/env python3
# tools/reimplement.py
import os, re, json, argparse
from pathlib import Path
import requests

FUNC_RE = re.compile(r"^(\w[\w\s\*]+)\s+(\w+)\s*\(([^)]*)\)\s*{", re.M)

SAFE_STYLE = (
    "- Avoid undefined behavior (bounds checks; no uninitialized reads; no UB casts)\n"
    "- Check all return codes; propagate errors gracefully\n"
    "- No magic constants: use local consts or #define with names\n"
    "- Prefer clear variable names; keep functions side-effect minimal\n"
    "- Log errors with comments like /* LOG: ... */ instead of real I/O\n"
    "- Keep to C89/C99-compatible constructs unless required\n"
)

def call_llm(endpoint, model, name, sig, meta, module, max_tokens=256, timeout=120):
    prompt = (
        "Re-implement this C function body based on metadata.\n"
        f"Module: {module}\n"
        f"Function: {name}\n"
        f"Signature: {sig}\n"
        f"Inputs: {', '.join(meta.get('inputs', []))}\n"
        f"Outputs: {', '.join(meta.get('outputs', []))}\n"
        f"Side-effects: {', '.join(meta.get('side_effects', []))}\n"
        f"Evidence: {'; '.join(list(map(str, meta.get('evidence', [])))[:3])}\n\n"
        "Style:\n" + SAFE_STYLE + "\n"
        "Return only a valid C function body (do not repeat the signature)."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an expert C programmer. Output only compilable code."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    r = requests.post(endpoint, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

def load_labels(path: Path):
    labels = {}
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            nm = obj.get("name")
            if nm: labels[nm] = obj
    return labels

def module_from_relpath(path_in: Path, src_root: Path) -> str:
    try:
        rel = path_in.relative_to(src_root)
        # e.g., "net/http/client.c" → "net/http"
        parent = rel.parent.as_posix()
        return parent if parent != "." else rel.stem
    except Exception:
        return path_in.stem

def process_sources(src_dir: Path, out_dir: Path, labels, endpoint, model):
    out_dir.mkdir(parents=True, exist_ok=True)
    files = [p for p in src_dir.rglob("*.c")]
    total = len(files)
    for idx, path_in in enumerate(files, 1):
        code = path_in.read_text(encoding="utf-8", errors="ignore")
        new_code = code
        modctx = module_from_relpath(path_in, src_dir)
        for m in FUNC_RE.finditer(code):
            ret, name, args = m.groups()
            sig = f"{ret.strip()} {name}({args.strip()})"
            if name in labels:
                try:
                    body = call_llm(
                        endpoint, model, name, sig, labels[name], modctx,
                        max_tokens=int(os.getenv("REIMPL_MAX_TOKENS", "256"))
                    )
                    header = m.group(0)  # includes opening brace
                    replacement = f"{sig} {{\n{body}\n}}"
                    new_code = new_code.replace(header, replacement, 1)
                except Exception:
                    pass
        out_path = out_dir / path_in.relative_to(src_dir)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(new_code, encoding="utf-8")
        if (idx % max(1, total // 25) == 0) or (idx == total):
            print(f"[reimpl] progress {idx}/{total}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-dir", default="work/recovered_project/src")
    ap.add_argument("--out-dir", default="work/recovered_project_impl/src")
    ap.add_argument("--labels",  default="work/hunt/functions.labeled.jsonl")
    ap.add_argument("--endpoint", default=os.getenv("LLM_ENDPOINT", "http://127.0.0.1:8080/v1/chat/completions"))
    ap.add_argument("--model",    default=os.getenv("LLM_MODEL", "qwen3-14b"))
    args = ap.parse_args()

    labels = load_labels(Path(args.labels))
    process_sources(Path(args.src_dir), Path(args.out_dir), labels, args.endpoint, args.model)

if __name__ == "__main__":
    main()

