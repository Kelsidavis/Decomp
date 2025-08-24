# tools/function_hunt/enrich_floss.py
import json, bisect

def load_floss_strings(path):
    try:
        data = json.load(open(path, 'r', encoding='utf-8'))
    except Exception:
        return []
    out = []
    # FLOSS JSON varies; prefer fields that contain a VA/offset and the string text.
    # Try common shapes conservatively.
    candidates = []
    for k in ("strings", "decoded_strings", "stack_strings", "tight_strings"):
        v = data.get(k)
        if isinstance(v, list):
            candidates.extend(v)
    for s in candidates:
        text = s.get("string") or s.get("decoded") or s.get("value") or ""
        va   = (s.get("va") or s.get("address") or
               (s.get("function") or {}).get("va"))
        if text and isinstance(text, str) and va:
            out.append((int(va), text))
    return out

def attach_floss(funcs, floss_pairs, max_per_fn=20):
    # funcs: list of dicts with 'start','end','addr','evidence'
    # build sorted starts for binary search
    starts = [f['start'] for f in funcs]
    for va, s in floss_pairs:
        i = bisect.bisect_right(starts, va) - 1
        if 0 <= i < len(funcs):
            f = funcs[i]
            if f['start'] <= va < f['end']:
                ev = f.setdefault('evidence', {})
                lst = ev.setdefault('strings_decoded', [])
                if s not in lst:
                    lst.append(s)
                    if len(lst) > max_per_fn:
                        del lst[0:len(lst)-max_per_fn]
    return funcs

