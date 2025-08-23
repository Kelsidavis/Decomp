#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_windows_build.py <recovered_project> [imports.json]

- Copies include/src/assets from recovered_project → recovered_project_win/
- Optionally generates a .rc with the first dumped icon
- Always links common Windows system import libs (MinGW)
- Reads imports.json to add specific SDK libs when present in mapping
- Emits optional FMOD/DIVX blocks (USE_FMOD/USE_DIVX) to link real SDKs if provided
- Generates vendor dyn shims (LoadLibrary/GetProcAddress) for non-mapped DLLs
"""

import json, pathlib, re, sys, shutil

# Map well-known system DLLs → MinGW import libs
SDK_MAP = {
    "KERNEL32.DLL":"kernel32", "USER32.DLL":"user32", "GDI32.DLL":"gdi32",
    "ADVAPI32.DLL":"advapi32", "COMCTL32.DLL":"comctl32", "SHELL32.DLL":"shell32",
    "WSOCK32.DLL":"wsock32",   "WS2_32.DLL":"ws2_32",  "OPENGL32.DLL":"opengl32",
    "IMM32.DLL":"imm32",       "WINMM.DLL":"winmm",    "WININET.DLL":"wininet",
    "COMDLG32.DLL":"comdlg32", "OLE32.DLL":"ole32",    "OLEAUT32.DLL":"oleaut32",
    "SHLWAPI.DLL":"shlwapi",   "IPHLPAPI.DLL":"iphlpapi", "CRYPT32.DLL":"crypt32",
}

# Always link these (good default set)
COMMON_WIN_LIBS = [
    "kernel32","user32","gdi32","comctl32","shell32","advapi32",
    "wsock32","winmm","imm32","opengl32","wininet"
]

def load_imports(path: pathlib.Path):
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        # expect {"modules": {"DLL": ["Func", ...], ...}}
        return obj.get("modules", {})
    except Exception:
        return {}

def guess_icon(assets_root: pathlib.Path):
    # Prefer .ico created by the normalizer
    icos = list((assets_root/"pe_resources").glob("*.ico"))
    if icos:
        return icos[0]
    # Otherwise any .ico under assets
    icos = list(assets_root.rglob("*.ico"))
    return icos[0] if icos else None

def sanitize(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def mk_vendor_shims(modules: dict, out_c: pathlib.Path) -> bool:
    """Emit a single dyn_shims.c that lazy-loads vendor DLLs and exports FARPROCs."""
    lines = ['#include <windows.h>', '#include <stdio.h>', '']
    had_any = False

    for dll, funcs in sorted(modules.items()):
        if dll.upper() in SDK_MAP:
            # System libs are linked, no shim required.
            continue
        had_any = True
        var = "h" + sanitize(dll.split('.')[0])
        lines.append(f"static HMODULE {var} = NULL;")
        for f in sorted(funcs):
            if not f or f.startswith("ORDINAL_"):
                continue
            lines.append(f"static FARPROC p_{sanitize(f)} = NULL;")
        lines += [
            "",
            "static FARPROC req(HMODULE h, const char* name){",
            '  FARPROC p = GetProcAddress(h, name);',
            '  if(!p) fprintf(stderr, "[vendor] missing %s\\n", name);',
            "  return p;",
            "}",
            ""
        ]
        dll_lit = dll  # keep case as-is
        lines += [f"int load_{sanitize(dll)}(void){{",
                  f"  if({var}) return 0;",
                  f"  {var} = LoadLibraryA(\"{dll_lit}\");",
                  f"  if(!{var}) return -1;"]
        for f in sorted(funcs):
            if not f or f.startswith("ORDINAL_"):
                continue
            lines.append(f"  p_{sanitize(f)} = req({var}, \"{f}\");")
        lines += ["  return 0;", "}", ""]

    if not had_any:
        return False

    out_c.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True

def write_cmakelists(dst_root: pathlib.Path, link_libs, has_rc: bool, has_vendor: bool):
    cm = []
    app_name = "recovered"  # constant exe name

    cm.append("cmake_minimum_required(VERSION 3.16)")
    cm.append("project(recovered_project_win CXX)")
    cm.append("set(CMAKE_C_STANDARD 11)")
    cm.append("set(CMAKE_CXX_STANDARD 17)")
    cm.append("add_definitions(-DUNICODE -D_UNICODE)")
    cm.append("include_directories(${CMAKE_SOURCE_DIR}/include)")
    cm.append('file(GLOB SRC "${CMAKE_SOURCE_DIR}/src/*.c" "${CMAKE_SOURCE_DIR}/src/*.cpp")')

    if has_rc:
        cm.append('set(RC_FILE "${CMAKE_SOURCE_DIR}/res/app.rc")')
        cm.append(f'add_executable({app_name} WIN32 ${{SRC}} ${{RC_FILE}})')
    else:
        cm.append(f'add_executable({app_name} WIN32 ${{SRC}})')

    # Always link a robust set of system libs, plus those inferred from imports.json
    all_libs = sorted(set(link_libs).union(COMMON_WIN_LIBS))
    if all_libs:
        cm.append(f"target_link_libraries({app_name} " + " ".join(all_libs) + ")")

    # Vendor shim fallback (only if we generated it)
    if has_vendor:
        cm.append(f'if (EXISTS "${{CMAKE_SOURCE_DIR}}/vendor/dyn_shims.c")')
        cm.append(f'  target_sources({app_name} PRIVATE ${{CMAKE_SOURCE_DIR}}/vendor/dyn_shims.c)')
        cm.append("endif()")

    # ---- FMOD SDK (toggleable) ----
    cm.append('option(USE_FMOD "Link FMOD SDK if present" ON)')
    cm.append('set(FMOD_ROOT "${CMAKE_SOURCE_DIR}/third_party/fmod" CACHE PATH "FMOD SDK root")')
    cm.append('if (USE_FMOD AND EXISTS "${FMOD_ROOT}/include/fmod.h")')
    cm.append('  target_include_directories(recovered PRIVATE ${FMOD_ROOT}/include)')
    cm.append('  if (CMAKE_SIZEOF_VOID_P EQUAL 8)')
    cm.append('    target_link_directories(recovered PRIVATE ${FMOD_ROOT}/lib/win64)')
    cm.append('  else()')
    cm.append('    target_link_directories(recovered PRIVATE ${FMOD_ROOT}/lib/win32)')
    cm.append('  endif()')
    cm.append('  # Adjust lib name to your SDK layout (fmod_vc / fmod / fmodstudio)')
    cm.append('  target_link_libraries(recovered fmod_vc)')
    cm.append('  target_compile_definitions(recovered PRIVATE HAVE_FMOD=1)')
    cm.append('endif()')

    # ---- DivX SDK (usually absent; OFF by default) ----
    cm.append('option(USE_DIVX "Link DivX SDK if present" OFF)')
    cm.append('set(DIVX_ROOT "${CMAKE_SOURCE_DIR}/third_party/divx" CACHE PATH "DivX SDK root")')
    cm.append('if (USE_DIVX AND EXISTS "${DIVX_ROOT}/include")')
    cm.append('  target_include_directories(recovered PRIVATE ${DIVX_ROOT}/include)')
    cm.append('  target_link_directories(recovered PRIVATE ${DIVX_ROOT}/lib/win64)')
    cm.append('  target_link_libraries(recovered divxdecoder)')
    cm.append('  target_compile_definitions(recovered PRIVATE HAVE_DIVX=1)')
    cm.append('endif()')

    (dst_root / "CMakeLists.txt").write_text("\n".join(cm) + "\n", encoding="utf-8")

def copy_tree(src_dir: pathlib.Path, dst_dir: pathlib.Path):
    if not src_dir.exists():
        return
    for p in src_dir.rglob("*"):
        rel = p.relative_to(src_dir)
        d = dst_dir / rel
        if p.is_dir():
            d.mkdir(parents=True, exist_ok=True)
        else:
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, d)

def main():
    if len(sys.argv) not in (2, 3):
        print("Usage: generate_windows_build.py <recovered_project> [imports.json]")
        sys.exit(0)

    proj = pathlib.Path(sys.argv[1]).resolve()
    imports_json = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) == 3 else None

    out = proj.parent / "recovered_project_win"
    out.mkdir(exist_ok=True)

    # copy include/src/assets into recovered_project_win/
    for sub in ("include", "src", "assets"):
        copy_tree(proj / sub, out / sub)

    # Parse imports → map to link libs + collect vendor DLLs
    modules = load_imports(imports_json) if (imports_json and imports_json.exists()) else {}
    link_libs = set()
    vendor = {}
    for dll, funcs in modules.items():
        dll_up = dll.upper()
        if dll_up in SDK_MAP:
            link_libs.add(SDK_MAP[dll_up])
        else:
            vendor[dll] = funcs

    # Optional: create .rc with icon if available
    ico = guess_icon(out / "assets")
    has_rc = False
    if ico:
        (out / "res").mkdir(exist_ok=True)
        (out / "res" / "app.rc").write_text(
            f'#include <windows.h>\nIDI_APPICON ICON "{ico}"\n', encoding="utf-8"
        )
        has_rc = True

    # Vendor shims (only if we actually have vendor DLLs)
    has_vendor = False
    if vendor:
        vend_dir = out / "vendor"
        vend_dir.mkdir(exist_ok=True)
        has_vendor = mk_vendor_shims(vendor, vend_dir / "dyn_shims.c")

    # Write CMakeLists
    write_cmakelists(out, link_libs, has_rc, has_vendor)

    print(f"[✓] Windows build scaffold → {out}")
    if vendor:
        print(f"[i] Dynamic wrappers generated for: {', '.join(sorted(vendor))}")
    if link_libs:
        print(f"[i] SDK libs requested from imports.json: {', '.join(sorted(link_libs))}")
    print(f"[i] Always linking common system libs: {', '.join(COMMON_WIN_LIBS)}")

if __name__ == "__main__":
    main()

