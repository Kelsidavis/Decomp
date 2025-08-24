#!/usr/bin/env python3
import os, re, json, requests, argparse

def call_llm(endpoint, model, name, sig, meta):
    prompt = f"""Re-implement this C function based on metadata.
Name: {name}
Signature: {sig}
Inputs: {', '.join(meta.get('inputs', []))}
Outputs: {', '.join(meta.get('outputs', []))}
Side-effects: {', '.join(meta.get('side_effects', []))}
Evidence: {meta.get('evidence', '')}

Return a valid C function body only (no commentary)."""
    payload = {
        "model": model,
        "messages": [
            {"role":"system","content":"You are an expert C programmer."},
            {"role":"user","content": prompt}
        ],
        "max_tokens": 256,
        "temperature": 0.2,
        "response_format": {"type":"text"}
    }
    r = requests.post(endpoint, json=payload, timeout=60)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

def load_labels(path):
    labels = {}
    with open(path) as f:
        for line in f:
            try:
                obj = json.loads(line)
                if "name" in obj and obj["name"]:
                    labels[obj["name"]] = obj
            except json.JSONDecodeError:
                continue
    return labels

def process_sources(src_dir, out_dir, labels, endpoint, model):
    os.makedirs(out_dir, exist_ok=True)
    func_re = re.compile(r"^(\w[\w\s\*]+)\s+(\w+)\s*\(([^)]*)\)\s*{", re.M)

    for root, _, files in os.walk(src_dir):
        for fn in files:
            if not fn.endswith(".c"): continue
            path_in = os.path.join(root, fn)
            path_out = os.path.join(out_dir, fn)
            with open(path_in) as f: code = f.read()

            new_code = code
            for m in func_re.finditer(code):
                ret, name, args = m.groups()
                sig = f"{ret.strip()} {name}({args.strip()})"
                if name in labels:
                    print(f"[reimpl] {name} → calling LLM…")
                    body = call_llm(endpoint, model, name, sig, labels[name])
                    new_code = new_code.replace(m.group(0)+"\n    // TODO", sig + " {\n" + body + "\n}")
            with open(path_out, "w") as f: f.write(new_code)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-dir", default="work/recovered_project/src")
    ap.add_argument("--out-dir", default="work/recovered_project_impl/src")
    ap.add_argument("--labels", default="work/hunt/functions.labeled.jsonl")
    ap.add_argument("--endpoint", default=os.getenv("LLM_ENDPOINT", "http://127.0.0.1:8080/v1/chat/completions"))
    ap.add_argument("--model", default=os.getenv("LLM_MODEL", "qwen3-14b"))
    args = ap.parse_args()

    labels = load_labels(args.labels)
    process_sources(args.src_dir, args.out_dir, labels, args.endpoint, args.model)

if __name__ == "__main__":
    main()

