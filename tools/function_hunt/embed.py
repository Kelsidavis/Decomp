import json, os
import numpy as np

def _toy_embed(text):
    # placeholder: hash-based bag-of-words to keep it local/offline
    # swap with sentence-transformers later
    tokens = text.lower().split()
    vec = np.zeros(256, dtype=np.float32)
    for t in tokens[:512]:
        vec[hash(t) % 256] += 1.0
    return vec / (np.linalg.norm(vec)+1e-9)

def build_index(funcs, out_dir):
    import faiss
    vecs, meta = [], []
    for i,f in enumerate(funcs):
        basis = " ".join(f.get("imports", [])) + " " + " ".join(f.get("strings", [])[:50]) + " " + f.get("snippet","")[:1000]
        vecs.append(_toy_embed(basis))
        meta.append({"idx": i, "name": f["name"], "addr": f["address"]})
    X = np.vstack(vecs)
    idx = faiss.IndexFlatIP(X.shape[1]); idx.add(X)
    faiss.write_index(idx, os.path.join(out_dir, "vectors.faiss"))
    with open(os.path.join(out_dir, "meta.jsonl"), "w") as w:
        for m in meta: w.write(json.dumps(m)+"\n")

