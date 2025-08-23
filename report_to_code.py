#!/usr/bin/env python3
"""
Convert a Markdown decompilation report (like the one produced by explain_with_llm.py)
into a C/C++ project scaffold:

project/
  include/recovered.h         # aggregate prototypes
  src/func_<name>.c(pp)       # stubs, pseudocode embedded as comments
  Makefile                    # basic build

Heuristics:
- Function sections start with:   ## <function_name> (0xADDR)
- Inside each section, looks for:
  "Clean prototype" or "Prototype" → first code block after that line
  "Pseudocode"                     → first code block after that line
- If no prototype found, synthesizes: void <name>(void);
- Merges multiple chunks for the same function.

Usage:
  python3 report_to_code.py path/to/report.md --out recovered_project --lang c|cpp
"""

import argparse, os, re, pathlib

H2_RE = re.compile(r'^\s*##\s+(.+?)(?:\s*\((0x[0-9A-Fa-f]+)\))?\s*$', re.M)
CODEBLOCK_RE = re.compile(r'```(?:[a-zA-Z0-9_+\-]*)\n(.*?)\n```', re.S)
SECTION_SPLIT_RE = re.compile(r'(^##\s+.+?$)', re.M)

def sanitize_ident(name: str) -> str:
    clean = re.sub(r'[^A-Za-z0-9_]', '_', name.strip())
    if not clean or not re.match(r'[A-Za-z_]', clean[0]):
        clean = f'func_{clean}'
    return clean

def extract_sections(md: str):
    parts = SECTION_SPLIT_RE.split(md)
    sections = []
    i = 1
    while i < len(parts):
        header = parts[i].strip()
        body = parts[i+1] if i+1 < len(parts) else ''
        m = H2_RE.match(header)
        if m:
            name = m.group(1).strip()
            addr = m.group(2) or ''
            sections.append((name, addr, body))
        i += 2
    return sections

def find_codeblock_after(label: str, body: str):
    lines = body.splitlines()
    idx = None
    lab = label.lower()
    for i, line in enumerate(lines):
        if lab in line.lower():
            idx = i
            break
    if idx is None:
        return None
    tail = "\n".join(lines[idx+1:])
    m = CODEBLOCK_RE.search(tail)
    return m.group(1).strip() if m else None

def first_codeblock(body: str):
    m = CODEBLOCK_RE.search(body)
    return m.group(1).strip() if m else None

def guess_prototype(prototype_block: str, name: str):
    if prototype_block:
        for line in prototype_block.splitlines():
            line = line.strip().rstrip(';')
            if '(' in line and ')' in line and not line.startswith('//'):
                return line + ';'
    return f'void {sanitize_ident(name)}(void);'

def gen_source(name: str, proto: str, pseudocode: str, lang: str = 'c'):
    base = sanitize_ident(name)
    if lang == 'cpp':
        ext = 'cpp'
    else:
        ext = 'c'

    # Header: prototypes go into include/recovered.h (aggregate)
    # Per-file header optional; we keep it simple.

    # Source text with pseudocode in comments
    src = []
    src.append('/*')
    src.append(f' * Function: {name}')
    src.append(' *')
    src.append(' * Pseudocode recovered by LLM (needs manual cleanup):')
    if pseudocode:
        for line in pseudocode.splitlines():
            src.append(' * ' + line)
    else:
        src.append(' * (no pseudocode available)')
    src.append(' */\n')

    src.append('#include "recovered.h"\n')

    sig = proto.rstrip(';')
    src.append(sig)
    src.append('{')
    src.append('    // TODO: implement according to pseudocode above')
    src.append('}\n')
    return base, "\n".join(src), ext

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('report_md', help='Path to report.md')
    ap.add_argument('--out', default='recovered_project', help='Output project directory')
    ap.add_argument('--lang', choices=['c','cpp'], default='c')
    args = ap.parse_args()

    md = open(args.report_md, 'r', encoding='utf-8', errors='ignore').read()
    sections = extract_sections(md)
    if not sections:
        raise SystemExit("No function sections (## ...) found in report.md")

    merged = {}
    for name, addr, body in sections:
        key = name.strip()
        proto_block = (find_codeblock_after('Clean prototype', body)
                       or find_codeblock_after('Prototype', body))
        pseudo_block = (find_codeblock_after('Pseudocode', body)
                        or find_codeblock_after('Pseudo-code', body)
                        or find_codeblock_after('Pseudo code', body)
                        or first_codeblock(body))
        d = merged.setdefault(key, {'addr': addr, 'protos': [], 'pseudos': []})
        if proto_block: d['protos'].append(proto_block)
        if pseudo_block: d['pseudos'].append(pseudo_block)

    out = pathlib.Path(args.out)
    inc = out / 'include'
    src = out / 'src'
    inc.mkdir(parents=True, exist_ok=True)
    src.mkdir(parents=True, exist_ok=True)

    recovered_h = ['#ifndef RECOVERED_H', '#define RECOVERED_H', '', '/* Aggregate prototypes (auto-generated) */']

    index_lines = ['# Recovered Code Index', '', '| Function | File | Address |', '|---|---|---|']

    for name, d in merged.items():
        proto = None
        if d['protos']:
            proto = sorted(d['protos'], key=len, reverse=True)[0]
        proto = guess_prototype(proto, name)
        pseudocode = "\n".join(d['pseudos']) if d['pseudos'] else ''

        base, src_text, ext = gen_source(name, proto, pseudocode, args.lang)
        (src / f'func_{base}.{ext}').write_text(src_text, encoding='utf-8')
        recovered_h.append(proto)
        index_lines.append(f"| `{name}` | `src/func_{base}.{ext}` | {d['addr'] or ''} |")

    recovered_h.append('\n#endif /* RECOVERED_H */\n')
    (inc / 'recovered.h').write_text("\n".join(recovered_h), encoding='utf-8')

    makefile = (
        "CC=gcc\n"
        "CFLAGS=-Wall -Wextra -O2 -Iinclude\n"
        "SRCS=$(wildcard src/*.c)\n"
        "OBJS=$(SRCS:.c=.o)\n"
        "BIN=recovered_bin\n\n"
        "all: $(BIN)\n\n"
        "$(BIN): $(OBJS)\n"
        "\t$(CC) $(CFLAGS) -o $@ $^\n\n"
        "clean:\n"
        "\trm -f $(OBJS) $(BIN)\n"
    )
    if args.lang == 'cpp':
        makefile = makefile.replace('CC=gcc','CXX=g++') \
                           .replace('$(wildcard src/*.c)','$(wildcard src/*.cpp)') \
                           .replace('OBJS=$(SRCS:.c=.o)','OBJS=$(SRCS:.cpp=.o)') \
                           .replace('$(CC)','$(CXX)')
    (out / 'Makefile').write_text(makefile, encoding='utf-8')

    (out / 'README.md').write_text("\n".join(index_lines) + "\n", encoding='utf-8')

    print(f"[✓] Wrote: {out}")
    print("  - include/recovered.h")
    print("  - src/*.c(pp)")
    print("  - Makefile")
    print("Build with:  cd", args.out, "&& make")

if __name__ == '__main__':
    main()

