#!/usr/bin/env python3
"""
External API Resolver - Generate proper function declarations for external APIs.

Analyzes the generated source code and creates proper external API declarations
based on function names and calling conventions found in the recovered project.
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

def load_api_database(api_db_path: Path) -> Dict:
    """Load API signature database"""
    with open(api_db_path, 'r') as f:
        return json.load(f)

def extract_external_function_calls(source_files: List[Path]) -> Dict[str, Set[str]]:
    """
    Extract external API function calls from source files.
    Returns: {library: set(function_names)}
    """
    api_calls = defaultdict(set)
    
    # Known API prefixes and their libraries
    api_prefixes = {
        'FSOUND_': 'fmod',
        'GetCurrentProcess': 'kernel32',
        'GetCurrentThread': 'kernel32', 
        'GetModuleHandle': 'kernel32',
        'LoadLibrary': 'kernel32',
        'FreeLibrary': 'kernel32',
        'GetProcAddress': 'kernel32',
        'CreateFile': 'kernel32',
        'ReadFile': 'kernel32',
        'WriteFile': 'kernel32',
        'CloseHandle': 'kernel32',
        'GetLastError': 'kernel32',
        'SetLastError': 'kernel32',
        'GetTickCount': 'kernel32',
        'Sleep': 'kernel32',
        'ExitProcess': 'kernel32',
        'MessageBox': 'user32',
        'CreateWindow': 'user32',
        'FindWindow': 'user32',
        'GetWindowText': 'user32',
        'SetWindowText': 'user32',
        'ShowWindow': 'user32',
        'UpdateWindow': 'user32',
        'DestroyWindow': 'user32',
        'GetMessage': 'user32',
        'PeekMessage': 'user32',
        'TranslateMessage': 'user32',
        'DispatchMessage': 'user32',
    }
    
    for source_file in source_files:
        if not source_file.exists():
            continue
            
        try:
            content = source_file.read_text(encoding='utf-8', errors='ignore')
            
            # Extract function names from file names (like FSOUND_Init_12_0x7FDB84.c)
            filename = source_file.stem
            if '_0x' in filename:
                func_name = filename.split('_0x')[0]
                
                # Remove parameter count suffix (like _12)
                func_parts = func_name.split('_')
                if func_parts[-1].isdigit():
                    func_name = '_'.join(func_parts[:-1])
                
                # Match against known prefixes
                for prefix, library in api_prefixes.items():
                    if func_name.startswith(prefix):
                        api_calls[library].add(func_name)
                        break
                        
            # Also scan for function calls in comments/pseudocode
            # Look for patterns like FSOUND_Init(), GetCurrentProcessId(), etc.
            func_call_pattern = r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\('
            matches = re.findall(func_call_pattern, content)
            
            for func_name in matches:
                for prefix, library in api_prefixes.items():
                    if func_name.startswith(prefix):
                        api_calls[library].add(func_name)
                        break
                        
        except Exception as e:
            print(f"Warning: Failed to process {source_file}: {e}")
            
    return dict(api_calls)

def parse_stdcall_decoration(func_name: str) -> Tuple[str, Optional[int]]:
    """
    Parse stdcall decoration from function name.
    E.g., 'FSOUND_Init@12' -> ('FSOUND_Init', 12)
    """
    if '@' in func_name:
        parts = func_name.rsplit('@', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
    return func_name, None

def resolve_function_signature(func_name: str, api_db: Dict) -> Optional[Dict]:
    """
    Resolve function signature from API database.
    Returns signature info or None if not found.
    """
    clean_name, param_bytes = parse_stdcall_decoration(func_name)
    
    # Search through all APIs
    for api_name, api_info in api_db['apis'].items():
        functions = api_info.get('functions', {})
        
        # Direct match
        if clean_name in functions:
            sig_info = functions[clean_name].copy()
            sig_info['library'] = api_name
            sig_info['header'] = api_info['header']
            sig_info['calling_convention'] = api_info['calling_convention']
            return sig_info
            
        # Try case-insensitive match for Windows APIs
        for db_func_name, db_func_info in functions.items():
            if db_func_name.lower() == clean_name.lower():
                sig_info = db_func_info.copy()
                sig_info['library'] = api_name
                sig_info['header'] = api_info['header'] 
                sig_info['calling_convention'] = api_info['calling_convention']
                return sig_info
                
    return None

def generate_external_declarations(api_calls: Dict[str, Set[str]], api_db: Dict) -> Tuple[Dict[str, List[str]], Set[str], Dict[str, Set[str]]]:
    """
    Generate external function declarations.
    
    Returns:
    - declarations: {library: [declaration_lines]}
    - headers: set of header files needed
    - libraries: {library: set(functions)}
    """
    declarations = defaultdict(list)
    headers = set()
    libraries = defaultdict(set)
    unresolved = []
    
    for library, functions in api_calls.items():
        for func_name in sorted(functions):
            sig_info = resolve_function_signature(func_name, api_db)
            
            if sig_info:
                # Generate declaration
                calling_conv = ''
                if sig_info['calling_convention'] == 'stdcall':
                    calling_conv = '__stdcall '
                elif sig_info['calling_convention'] == 'fastcall':
                    calling_conv = '__fastcall '
                    
                declaration = f"extern {sig_info['return_type']} {calling_conv}{func_name}({', '.join(sig_info['parameters']) if sig_info['parameters'] else 'void'});"
                declarations[library].append(declaration)
                
                headers.add(sig_info['header'])
                libraries[sig_info['library']].add(func_name)
            else:
                # Generate generic declaration for unresolved functions
                clean_name, _ = parse_stdcall_decoration(func_name)
                generic_decl = f"extern void {clean_name}(void);  // FIXME: Unknown signature"
                declarations[library].append(generic_decl)
                unresolved.append(func_name)
                
    if unresolved:
        print(f"Warning: Could not resolve signatures for {len(unresolved)} functions:")
        for func in unresolved[:10]:  # Show first 10
            print(f"  {func}")
        if len(unresolved) > 10:
            print(f"  ... and {len(unresolved) - 10} more")
    
    return dict(declarations), headers, dict(libraries)

def generate_external_header(declarations: Dict[str, List[str]], headers: Set[str], output_path: Path):
    """Generate external_apis.h header file"""
    
    header_content = [
        "#ifndef EXTERNAL_APIS_H",
        "#define EXTERNAL_APIS_H",
        "",
        "/*",
        " * External API Function Declarations",
        " * Generated by resolve_external_apis.py",
        " */",
        ""
    ]
    
    # Add system headers
    system_headers = sorted(headers)
    if system_headers:
        header_content.append("/* System headers */")
        for header in system_headers:
            if header == 'windows.h':
                header_content.append("#ifdef _WIN32")
                header_content.append(f"#include <{header}>")
                header_content.append("#endif")
            else:
                header_content.append(f"#include <{header}>")
        header_content.append("")
    
    # Add compatibility defines for non-Windows systems
    header_content.extend([
        "/* Compatibility defines for cross-platform compilation */",
        "#ifndef _WIN32",
        "typedef void* HANDLE;",
        "typedef void* HWND;", 
        "typedef void* HMODULE;",
        "typedef void* HINSTANCE;",
        "typedef void* HMENU;",
        "typedef unsigned long DWORD;",
        "typedef int BOOL;",
        "typedef unsigned int UINT;",
        "typedef const char* LPCSTR;",
        "typedef const wchar_t* LPCWSTR;",
        "typedef char* LPSTR;",
        "typedef void* LPVOID;",
        "typedef const void* LPCVOID;",
        "typedef DWORD* LPDWORD;",
        "typedef void* LPOVERLAPPED;",
        "typedef void* LPSECURITY_ATTRIBUTES;",
        "typedef void* FARPROC;",
        "typedef void* LPMSG;",
        "typedef long LRESULT;",
        "#define __stdcall",
        "#define __fastcall",
        "#endif",
        ""
    ])
    
    # Add C++ compatibility
    header_content.extend([
        "#ifdef __cplusplus",
        "extern \"C\" {", 
        "#endif",
        ""
    ])
    
    # Add function declarations by library
    for library in sorted(declarations.keys()):
        decls = declarations[library]
        if decls:
            header_content.append(f"/* {library.upper()} API */")
            header_content.extend(decls)
            header_content.append("")
    
    # Close C++ compatibility
    header_content.extend([
        "#ifdef __cplusplus",
        "}",
        "#endif",
        "",
        "#endif /* EXTERNAL_APIS_H */"
    ])
    
    output_path.write_text('\n'.join(header_content), encoding='utf-8')

def generate_linkage_info(libraries: Dict[str, Set[str]], output_path: Path):
    """Generate linking information for build systems"""
    
    linkage_info = {
        "libraries": {},
        "build_flags": {
            "windows": {
                "libs": [],
                "link_flags": []
            },
            "linux": {
                "libs": [],
                "link_flags": []
            }
        }
    }
    
    # Map our library names to actual link libraries
    lib_mapping = {
        "fmod": {"windows": "fmod_vc", "linux": "fmod"},
        "kernel32": {"windows": "kernel32", "linux": None},
        "user32": {"windows": "user32", "linux": None},
        "gdi32": {"windows": "gdi32", "linux": None},
        "advapi32": {"windows": "advapi32", "linux": None},
        "shell32": {"windows": "shell32", "linux": None},
        "ole32": {"windows": "ole32", "linux": None},
        "oleaut32": {"windows": "oleaut32", "linux": None},
        "uuid": {"windows": "uuid", "linux": None},
        "winmm": {"windows": "winmm", "linux": None}
    }
    
    for lib_name, functions in libraries.items():
        linkage_info["libraries"][lib_name] = {
            "functions": list(functions),
            "count": len(functions)
        }
        
        if lib_name in lib_mapping:
            win_lib = lib_mapping[lib_name]["windows"]
            linux_lib = lib_mapping[lib_name]["linux"]
            
            if win_lib and win_lib not in linkage_info["build_flags"]["windows"]["libs"]:
                linkage_info["build_flags"]["windows"]["libs"].append(win_lib)
                
            if linux_lib and linux_lib not in linkage_info["build_flags"]["linux"]["libs"]:
                linkage_info["build_flags"]["linux"]["libs"].append(linux_lib)
    
    with open(output_path, 'w') as f:
        json.dump(linkage_info, f, indent=2, sort_keys=True)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <recovered_project_dir>")
        sys.exit(1)
        
    project_dir = Path(sys.argv[1])
    if not project_dir.exists():
        print(f"Error: Project directory not found: {project_dir}")
        sys.exit(1)
        
    src_dir = project_dir / "src"
    if not src_dir.exists():
        print(f"Error: Source directory not found: {src_dir}")
        sys.exit(1)
    
    # Load API database
    api_db_path = Path(__file__).parent / "api_signatures.json"
    if not api_db_path.exists():
        print(f"Error: API database not found: {api_db_path}")
        sys.exit(1)
        
    api_db = load_api_database(api_db_path)
    
    # Find all source files
    source_files = list(src_dir.glob("*.c")) + list(src_dir.glob("*.cpp"))
    print(f"Analyzing {len(source_files)} source files...")
    
    # Extract API calls
    api_calls = extract_external_function_calls(source_files)
    
    if not api_calls:
        print("No external API calls found.")
        return
        
    total_functions = sum(len(funcs) for funcs in api_calls.values())
    print(f"Found {total_functions} external API calls across {len(api_calls)} libraries:")
    for lib, funcs in api_calls.items():
        print(f"  {lib}: {len(funcs)} functions")
    
    # Resolve signatures
    declarations, headers, libraries = generate_external_declarations(api_calls, api_db)
    
    # Generate header file
    include_dir = project_dir / "include"
    include_dir.mkdir(exist_ok=True)
    
    header_path = include_dir / "external_apis.h"
    generate_external_header(declarations, headers, header_path)
    print(f"Generated: {header_path}")
    
    # Generate linkage info
    linkage_path = project_dir / "external_linkage.json"
    generate_linkage_info(libraries, linkage_path)
    print(f"Generated: {linkage_path}")
    
    print(f"\\nSummary:")
    print(f"  Headers needed: {len(headers)}")
    print(f"  Libraries: {len(libraries)}")
    print(f"  Total API functions: {sum(len(funcs) for funcs in libraries.values())}")
    
    print("\\nTo use in your project:")
    print('#include "external_apis.h"')

if __name__ == '__main__':
    main()