#!/usr/bin/env python3
"""
Language detection based on symbol analysis and calling conventions.
Analyzes Ghidra export JSON to determine if the binary was originally C or C++.
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

def detect_cpp_mangling(symbol: str) -> bool:
    """Detect C++ mangled symbols (Itanium/GCC style)"""
    # Itanium C++ ABI mangling patterns
    if re.match(r'^_Z[NSTF]', symbol):  # Standard C++ mangling
        return True
    if re.match(r'^_Z\d+', symbol):    # Simple function name mangling
        return True
    return False

def detect_msvc_mangling(symbol: str) -> bool:
    """Detect Microsoft Visual C++ mangled symbols"""
    # MSVC C++ mangling patterns
    if symbol.startswith('?'):  # MSVC C++ symbol prefix
        return True
    # Exclude stdcall decorations like @32, @20 which are C decorations, not C++ mangling
    if '@' in symbol and not symbol.startswith('_') and not re.match(r'.*@\d+$', symbol):
        return True
    return False

def analyze_calling_conventions(functions: List[Dict]) -> Tuple[int, int, int]:
    """Count calling convention usage"""
    thiscall_count = 0
    fastcall_count = 0  
    stdcall_count = 0
    
    for func in functions:
        cc = func.get('calling_convention', '').lower()
        if 'thiscall' in cc:
            thiscall_count += 1
        elif 'fastcall' in cc:
            fastcall_count += 1
        elif 'stdcall' in cc:
            stdcall_count += 1
            
    return thiscall_count, fastcall_count, stdcall_count

def detect_cpp_keywords(pseudo_code: str) -> int:
    """Count C++ specific keywords in decompiled code"""
    cpp_patterns = [
        r'\bclass\s+\w+',
        r'\bnamespace\s+\w+', 
        r'\btemplate\s*<',
        r'\bstd::', 
        r'\boperator\s*[+\-*/=<>!]+',
        r'\bvirtual\s+',
        r'\bpublic:|private:|protected:',
        r'\binline\s+',
        r'\bexplicit\s+',
        r'\btypename\s+',
        r'\bconst_cast|static_cast|dynamic_cast|reinterpret_cast',
        r'\bnew\s+\w+|delete\s+',
        r'\bthrow\s+',
        r'\bcatch\s*\(',
        r'\btry\s*{',
        r'\bthis\s*->',
        r'\b\w+::\w+',  # Scope resolution
    ]
    
    cpp_score = 0
    for pattern in cpp_patterns:
        matches = re.findall(pattern, pseudo_code, re.IGNORECASE | re.MULTILINE)
        cpp_score += len(matches)
    
    return cpp_score

def analyze_function_names(functions: List[Dict]) -> Tuple[int, int]:
    """Analyze function naming patterns"""
    cpp_mangled = 0
    cpp_patterns = 0
    
    for func in functions:
        name = func.get('name', '')
        
        # Check for mangled symbols
        if detect_cpp_mangling(name) or detect_msvc_mangling(name):
            cpp_mangled += 1
            
        # Check for C++ naming patterns
        if '::' in name:  # Scope resolution
            cpp_patterns += 1
        if re.match(r'.*operator[+\-*/=<>!]+.*', name):  # Operator overloading
            cpp_patterns += 1
        if name.startswith('~'):  # Destructor
            cpp_patterns += 1
        if re.match(r'.*::\w+\(.*\)$', name):  # Method calls
            cpp_patterns += 1
            
    return cpp_mangled, cpp_patterns

def detect_language_from_export(export_path: Path) -> Tuple[str, Dict]:
    """
    Detect programming language from Ghidra export JSON.
    Returns: (language, analysis_details)
    """
    
    with open(export_path, 'r') as f:
        data = json.load(f)
    
    functions = data.get('functions', [])
    
    if not functions:
        return 'c', {'reason': 'no_functions', 'confidence': 0.0}
    
    # Analysis metrics
    total_functions = len(functions)
    sample_size = min(1000, total_functions)  # Analyze first 1000 functions
    sample_functions = functions[:sample_size]
    
    # 1. Analyze function names for mangling
    cpp_mangled, cpp_patterns = analyze_function_names(sample_functions)
    
    # 2. Analyze calling conventions
    thiscall_count, fastcall_count, stdcall_count = analyze_calling_conventions(sample_functions)
    
    # 3. Analyze pseudo code for C++ keywords (sample smaller set)
    cpp_keywords_score = 0
    code_sample_size = min(100, len(sample_functions))
    for func in sample_functions[:code_sample_size]:
        pseudo = func.get('pseudo', '') or func.get('decompiled_c', '')
        cpp_keywords_score += detect_cpp_keywords(pseudo)
    
    # Scoring system
    cpp_score = 0.0
    analysis = {}
    
    # Symbol mangling (strong indicator)
    if cpp_mangled > 0:
        cpp_score += min(cpp_mangled / sample_size * 100, 50)  # Up to 50 points
        analysis['mangled_symbols'] = cpp_mangled
    
    # Calling conventions (moderate indicator)  
    if thiscall_count > 0:  # thiscall is C++ specific
        cpp_score += min(thiscall_count / sample_size * 30, 20)  # Up to 20 points
        analysis['thiscall_functions'] = thiscall_count
        
    # C++ naming patterns (moderate indicator)
    if cpp_patterns > 0:
        cpp_score += min(cpp_patterns / sample_size * 20, 15)  # Up to 15 points
        analysis['cpp_naming_patterns'] = cpp_patterns
    
    # C++ keywords in code (weak indicator, can be noisy)
    if cpp_keywords_score > 0:
        cpp_score += min(cpp_keywords_score / code_sample_size * 10, 10)  # Up to 10 points
        analysis['cpp_keywords'] = cpp_keywords_score
        
    # Statistical analysis
    analysis.update({
        'total_functions': total_functions,
        'sample_size': sample_size,
        'thiscall_count': thiscall_count,
        'fastcall_count': fastcall_count,
        'stdcall_count': stdcall_count,
        'cpp_score': cpp_score
    })
    
    # Decision thresholds
    if cpp_score >= 15.0:  # Strong C++ indicators
        language = 'cpp'
        confidence = min(cpp_score / 50.0, 1.0)  # Scale to 0-1
        analysis['reason'] = 'strong_cpp_indicators'
    elif cpp_score >= 5.0:   # Moderate C++ indicators  
        language = 'cpp'
        confidence = min(cpp_score / 30.0, 1.0)
        analysis['reason'] = 'moderate_cpp_indicators'
    else:
        language = 'c'       # Default to C
        confidence = 1.0 - min(cpp_score / 20.0, 0.8)  # Higher confidence with lower cpp_score
        analysis['reason'] = 'c_default'
    
    analysis['confidence'] = confidence
    
    return language, analysis

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ghidra_export.json> [--debug]")
        sys.exit(1)
        
    export_path = Path(sys.argv[1])
    debug = '--debug' in sys.argv
    
    if not export_path.exists():
        print(f"Error: Export file not found: {export_path}")
        sys.exit(1)
    
    try:
        language, analysis = detect_language_from_export(export_path)
        
        print(f"Detected language: {language.upper()}")
        print(f"Confidence: {analysis['confidence']:.2f}")
        print(f"Reason: {analysis['reason']}")
        print()
        print("Analysis details:")
        for key, value in sorted(analysis.items()):
            if key not in ['reason', 'confidence']:
                print(f"  {key}: {value}")
                
        # Debug mode: show actual mangled symbols found
        if debug and analysis.get('mangled_symbols', 0) > 0:
            print()
            print("Debug: Found mangled symbols:")
            with open(export_path, 'r') as f:
                data = json.load(f)
            functions = data.get('functions', [])
            sample_size = min(1000, len(functions))
            
            count = 0
            for func in functions[:sample_size]:
                name = func.get('name', '')
                if detect_cpp_mangling(name) or detect_msvc_mangling(name):
                    print(f"  {name}")
                    count += 1
                    if count >= 10:  # Limit output
                        remaining = analysis.get('mangled_symbols', 0) - count
                        if remaining > 0:
                            print(f"  ... and {remaining} more")
                        break
                
    except Exception as e:
        print(f"Error analyzing export: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()