#!/usr/bin/env python3
import sys, os, re, struct, json, pathlib

MIN = 32  # minimal bytes to keep (more aggressive)

def find_all(buf, sig):
    i = 0
    L = len(sig)
    while True:
        i = buf.find(sig, i)
        if i == -1: break
        yield i
        i += 1

def valid_png(b):
    if not b.startswith(b"\x89PNG\r\n\x1a\n"): return False
    return b.endswith(b"IEND\xaeB`\x82")

def valid_jpeg(b):
    if not b.startswith(b"\xff\xd8\xff"): return False
    if len(b) < 10: return False
    # Check for valid JPEG segment marker (not 0xFF which indicates corrupted/code data)
    third_byte = b[3]
    # Valid JPEG markers: E0-EF (JFIF/EXIF), C0-CF (SOF), DB (DQT), etc.
    return third_byte in [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 
                         0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
                         0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                         0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
                         0xDB, 0xC4, 0xDD]

def valid_bmp(b):
    if not b.startswith(b"BM"): return False
    if len(b) < 54: return False
    try:
        # Check if file size makes sense
        file_size = struct.unpack("<I", b[2:6])[0]
        if file_size != len(b): return False
        
        # Check if data offset is reasonable
        data_offset = struct.unpack("<I", b[10:14])[0]
        if data_offset < 54 or data_offset >= len(b): return False
        
        # Check if image dimensions are reasonable
        width = struct.unpack("<I", b[18:22])[0]
        height = struct.unpack("<I", b[22:26])[0]
        if width == 0 or height == 0 or width > 65535 or height > 65535: return False
        
        return True
    except:
        return False

def valid_zip(b):
    if not b.startswith(b"PK\x03\x04"): return False
    if len(b) < 30: return False
    try:
        # Basic ZIP local file header validation
        # Check if filename length is reasonable
        filename_len = struct.unpack("<H", b[26:28])[0]
        extra_len = struct.unpack("<H", b[28:30])[0]
        if filename_len > 1024 or extra_len > 1024: return False
        return True
    except:
        return False

def valid_ico(b):
    if not b.startswith(b"\x00\x00\x01\x00"): return False
    if len(b) < 6: return False
    try:
        count = struct.unpack("<H", b[4:6])[0]
        if count == 0 or count > 64: return False
        # Must have directory entries
        if len(b) < 6 + count * 16: return False
        return True
    except:
        return False

def valid_ttf(b):
    """Validate TrueType font - very strict validation to avoid false positives"""
    if not b.startswith(b"\x00\x01\x00\x00"): return False
    if len(b) < 1000: return False  # Real fonts are substantial
    
    try:
        # Immediate rejection if too many x86 opcodes (machine code pattern)
        x86_opcodes = {0x8b, 0x89, 0xeb, 0xe8, 0xe9, 0x83, 0x85, 0x33, 0x57, 0x55, 0x53, 0x50, 0x51, 0x52, 0xc3, 0xcc, 0x74, 0x75, 0x0f}
        first_32_opcodes = sum(1 for byte in b[4:36] if byte in x86_opcodes)
        if first_32_opcodes > 4:  # Very low threshold - machine code has many opcodes
            return False
        
        # Check font table structure (big endian)
        num_tables = struct.unpack(">H", b[4:6])[0]
        if num_tables < 4 or num_tables > 50:  # Real fonts need several tables
            return False
            
        # Must have enough space for table directory
        if len(b) < 12 + num_tables * 16:
            return False
            
        # Verify table tags and find required tables
        table_tags = []
        valid_tag_chars = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ')
        
        for i in range(num_tables):
            offset = 12 + i * 16
            if offset + 16 <= len(b):
                tag = b[offset:offset+4]
                # Font table tags should be printable ASCII
                if not all(c in valid_tag_chars for c in tag):
                    return False
                table_tags.append(tag)
        
        # Must have essential font tables
        table_set = set(table_tags)
        required_tables = {b'head', b'hhea', b'maxp'}
        if not all(table in table_set for table in required_tables):
            return False
            
        # Should have at least one glyph-related table
        glyph_tables = {b'glyf', b'CFF ', b'cmap', b'loca'}
        if not any(table in table_set for table in glyph_tables):
            return False
            
        return True
    except:
        return False

def valid_otf(b):
    """Validate OpenType font - check for OTTO signature and structure"""
    if not b.startswith(b"OTTO"): return False
    if len(b) < 12: return False
    
    try:
        # Similar validation logic for OTF
        num_tables = struct.unpack(">H", b[4:6])[0]
        if num_tables == 0 or num_tables > 100:
            return False
            
        if len(b) < 12 + num_tables * 16:
            return False
            
        return True
    except:
        return False

def valid_wav(b):
    if not b.startswith(b"RIFF"): return False
    if len(b) < 12: return False
    try:
        # Must be WAVE format
        if b[8:12] != b"WAVE": return False
        
        # Check RIFF size makes sense
        riff_size = struct.unpack("<I", b[4:8])[0]
        if riff_size < 4 or riff_size > len(b) - 8: return False
        
        return True
    except:
        return False

def valid_mp3(b):
    if len(b) < 4: return False
    
    # Check MP3 sync word and basic frame header
    if b.startswith(b"\xff\xfb") or b.startswith(b"\xff\xfa"):
        # MPEG-1 Layer 3 frame header validation
        if len(b) < 4: return False
        
        # Check if bytes 2-4 look like valid MP3 frame header vs x86 code
        # x86 code often has patterns like 8b xx (mov), 89 xx (mov), eb/e8/e9 (jumps)
        # MP3 frame headers have specific bit patterns for bitrate/sample rate
        
        # Common x86 opcodes that appear after MP3 sync words in code
        x86_patterns = [0x8b, 0x89, 0xeb, 0xe8, 0xe9, 0x83, 0x85, 0x33, 0x57, 0x55, 0x53, 0x50, 0x51, 0x52]
        
        # If byte 4 is a common x86 opcode, likely not MP3
        if len(b) >= 5 and b[4] in x86_patterns:
            return False
            
        # Check for reasonable MP3 frame header pattern
        byte2 = b[2]
        # Valid MP3 version/layer bits (bits 3-4 should be 01 for Layer 3)
        if (byte2 & 0x06) != 0x02:  # Layer 3 check
            return False
            
        # Check protection bit and other frame header consistency
        byte3 = b[3]
        # Bitrate index shouldn't be 1111 (invalid) or 0000 (free format, rare)
        bitrate_idx = (byte3 & 0xF0) >> 4
        if bitrate_idx == 0 or bitrate_idx == 15:
            return False
            
        return True
    
    elif b.startswith(b"ID3"):
        # ID3v2 tag - check for reasonable tag structure
        if len(b) < 10: return False
        
        # ID3v2 version should be reasonable (2.x, 3.x, 4.x)
        major_version = b[3]
        minor_version = b[4]
        if major_version < 2 or major_version > 4 or minor_version > 9:
            return False
            
        # Check if tag size makes sense
        if len(b) > 10:
            # ID3v2 uses syncsafe integers
            tag_size = (b[6] << 21) | (b[7] << 14) | (b[8] << 7) | b[9]
            if tag_size == 0 or tag_size > len(b) - 10:
                return False
                
        return True
    
    return False

def valid_ogg(b):
    if not b.startswith(b"OggS"): return False
    if len(b) < 27: return False  # Minimum Ogg page header size
    try:
        # Check Ogg page structure
        version = b[4]
        if version != 0: return False  # Should be version 0
        
        # Check page segments count is reasonable
        segments = b[26]
        if segments > 255: return False
        
        return True
    except:
        return False
def end_png(buf, off):
    # walk chunks until IEND
    i = off + 8
    n = len(buf)
    while i + 8 <= n:
        if i + 8 > n: break
        (clen,) = struct.unpack(">I", buf[i:i+4])
        ctype = buf[i+4:i+8]
        i += 8 + clen + 4
        if ctype == b"IEND":
            return i
    return None

def end_gif(buf, off):
    # ends with 0x3B
    end = buf.find(b"\x3B", off+6)
    return end+1 if end != -1 else None

def end_jpeg(buf, off):
    # find 0xFFD9
    i = buf.find(b"\xff\xd9", off+2)
    return i+2 if i != -1 else None

def end_bmp(buf, off):
    # BITMAPFILEHEADER: 14 bytes, at 2..6 is file size (little endian)
    if off+14 > len(buf): return None
    size = struct.unpack("<I", buf[off+2:off+6])[0]
    if size <= 14 or size > len(buf): 
        # Fallback: estimate size from bitmap info header
        if off+54 > len(buf): return None
        width = struct.unpack("<I", buf[off+18:off+22])[0] if off+22 <= len(buf) else 0
        height = struct.unpack("<I", buf[off+22:off+26])[0] if off+26 <= len(buf) else 0
        bpp = struct.unpack("<H", buf[off+28:off+30])[0] if off+30 <= len(buf) else 24
        if width > 0 and height > 0:
            estimated = 54 + ((width * bpp + 31) // 32) * 4 * height
            end = off + min(estimated, len(buf) - off, 1024*1024)  # Cap at 1MB
            return end if end > off + MIN else None
        return None
    end = off + size
    return end if end <= len(buf) else len(buf)

def end_riff_webp(buf, off):
    # RIFF xxxx WEBP - be more aggressive about WebP extraction
    if off+12 > len(buf): return None
    if buf[off:off+4] != b"RIFF": return None
    # Skip if it's actually a WAVE file
    if buf[off+8:off+12] == b"WAVE": return None
    # Only proceed if it's actually WEBP
    if buf[off+8:off+12] != b"WEBP": return None
    size = struct.unpack("<I", buf[off+4:off+8])[0]
    
    # Calculate expected end
    expected_end = off + 8 + size
    if expected_end <= len(buf) and size > 0:
        return expected_end
    
    # Aggressive fallback: scan for VP8/VP8L/VP8X chunks to find actual end
    pos = off + 12
    actual_end = pos
    while pos + 8 <= len(buf):
        if pos >= len(buf) - 8: break
        try:
            chunk_id = buf[pos:pos+4]
            chunk_size = struct.unpack("<I", buf[pos+4:pos+8])[0]
            if chunk_id in [b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF", b"ICCP", b"EXIF", b"XMP "]:
                actual_end = pos + 8 + ((chunk_size + 1) & ~1)  # WebP chunks are padded to even bytes
                pos = actual_end
            else:
                break
        except:
            break
    
    # If no chunks found, use heuristic based on next magic signatures
    if actual_end == off + 12:
        next_magics = [b"RIFF", b"\x89PNG", b"\xff\xd8\xff", b"BM", b"PK\x03\x04", b"GIF8"]
        for magic in next_magics:
            next_pos = buf.find(magic, off+12)
            if next_pos != -1:
                actual_end = next_pos
                break
        else:
            # Last resort: use size from header or reasonable estimate
            actual_end = min(off + max(size, 1024), len(buf))
    
    return actual_end if actual_end > off + MIN else None

def end_zip(buf, off):
    # scan to EOCD (PK\x05\x06)
    j = buf.find(b"PK\x05\x06", off+4)
    if j == -1: return None
    # EOCD size is variable; take end of EOCD min size (22 bytes) + comment
    if j + 22 > len(buf): return None
    comlen = struct.unpack("<H", buf[j+20:j+22])[0]
    end = j + 22 + comlen
    return end if end <= len(buf) else None

def end_pdf(buf, off):
    # find "%%EOF"
    j = buf.find(b"%%EOF", off+5)
    return j+5 if j != -1 else None

def end_gzip(buf, off):
    # naive: scan until next magic or EOF
    # proper parse is longer; this is a fallback
    n = len(buf)
    nexts = [n]
    for sig in (b"\x1f\x8b\x08", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"PK\x03\x04", b"%PDF-", b"RIFF"):
        j = buf.find(sig, off+3)
        if j != -1: nexts.append(j)
    e = min(nexts)
    return e if e-off >= MIN else None

def end_ico(buf, off):
    # ICO header: 6 bytes + count*16 bytes directory + image data
    if off+6 > len(buf): return None
    try:
        count = struct.unpack("<H", buf[off+4:off+6])[0]
        if count == 0 or count > 64: return None  # Reasonable limit
        
        dir_end = off + 6 + count * 16
        if dir_end > len(buf): return None
        
        # Find the furthest image data
        max_end = dir_end
        for i in range(count):
            dir_pos = off + 6 + i * 16
            if dir_pos + 16 > len(buf): break
            size = struct.unpack("<I", buf[dir_pos+8:dir_pos+12])[0]
            offset = struct.unpack("<I", buf[dir_pos+12:dir_pos+16])[0]
            if offset > 0 and size > 0:
                img_end = off + offset + size  # ICO offsets are relative to file start
                max_end = max(max_end, img_end)
        
        return max_end if max_end <= len(buf) else None
    except:
        return None

def end_wav(buf, off):
    # RIFF xxxx WAVE - only match if it's actually WAVE
    if off+12 > len(buf): return None
    if buf[off:off+4] != b"RIFF": return None
    if buf[off+8:off+12] != b"WAVE": return None  # Must be WAVE, not WEBP
    size = struct.unpack("<I", buf[off+4:off+8])[0]
    end = off + 8 + size
    return end if end <= len(buf) else len(buf)

def end_mp3(buf, off):
    # MP3 files can vary greatly, scan for next frame or reasonable max
    n = len(buf)
    nexts = [n]
    # Look for next magic signatures or MP3 frame sync
    for sig in (b"\xff\xfb", b"\xff\xfa", b"\x89PNG", b"\xff\xd8\xff", b"RIFF", b"PK\x03\x04"):
        j = buf.find(sig, off+4)
        if j != -1: nexts.append(j)
    # Also look for ID3v1 tag at end
    id3_end = buf.find(b"TAG", off+128)
    if id3_end != -1:
        nexts.append(id3_end + 128)
    e = min(nexts)
    return e if e-off >= MIN else None

def end_ogg(buf, off):
    # OggS format - scan for end of stream or next magic
    n = len(buf)
    nexts = [n]
    for sig in (b"OggS", b"\x89PNG", b"\xff\xd8\xff", b"RIFF", b"PK\x03\x04"):
        j = buf.find(sig, off+4)
        if j != -1: nexts.append(j)
    e = min(nexts)
    return e if e-off >= MIN else None

def end_flac(buf, off):
    # FLAC format - scan for next magic or reasonable end
    n = len(buf)
    nexts = [n]
    for sig in (b"fLaC", b"\x89PNG", b"\xff\xd8\xff", b"RIFF", b"PK\x03\x04"):
        j = buf.find(sig, off+4)
        if j != -1: nexts.append(j)
    e = min(nexts)
    return e if e-off >= MIN else None

# Additional format parsers for comprehensive scanning
def end_avi(buf, off):
    # AVI is RIFF + AVI format
    if off+12 > len(buf): return None
    if buf[off:off+4] != b"RIFF": return None
    if buf[off+8:off+12] != b"AVI ": return None
    size = struct.unpack("<I", buf[off+4:off+8])[0]
    end = off + 8 + size
    return end if end <= len(buf) else len(buf)

def end_exe(buf, off):
    # PE/DOS executable - find end by parsing PE structure
    if off+64 > len(buf): return None
    try:
        pe_offset = struct.unpack("<I", buf[off+60:off+64])[0]
        if off+pe_offset+24 > len(buf): return None
        if buf[off+pe_offset:off+pe_offset+4] != b"PE\x00\x00": return None
        # Very rough estimate - scan for next magic or use reasonable max
        n = len(buf)
        nexts = [n]
        for sig in (b"MZ", b"\x89PNG", b"RIFF", b"PK\x03\x04"):
            j = buf.find(sig, off+1024)  # Skip past headers
            if j != -1: nexts.append(j)
        e = min(nexts)
        return min(e, off + 50*1024*1024)  # Cap at 50MB
    except:
        return None

def end_dll(buf, off):
    # Same as EXE - PE format
    return end_exe(buf, off)

def end_cab(buf, off):
    # Microsoft Cabinet file
    if off+8 > len(buf): return None
    size = struct.unpack("<I", buf[off+8:off+12])[0] if off+12 <= len(buf) else 0
    if size == 0 or size > len(buf):
        # Fallback scan
        n = len(buf)
        nexts = [n]
        for sig in (b"MSCF", b"\x89PNG", b"RIFF", b"PK\x03\x04"):
            j = buf.find(sig, off+20)
            if j != -1: nexts.append(j)
        return min(nexts)
    return off + size

def end_rar(buf, off):
    # RAR archive - complex format, use heuristic
    n = len(buf)
    nexts = [n]
    for sig in (b"Rar!", b"\x89PNG", b"RIFF", b"PK\x03\x04"):
        j = buf.find(sig, off+7)
        if j != -1: nexts.append(j)
    e = min(nexts)
    return e if e-off >= MIN else None

def end_7z(buf, off):
    # 7-Zip archive
    n = len(buf)
    nexts = [n]
    for sig in (b"7z\xbc\xaf\x27\x1c", b"\x89PNG", b"RIFF", b"PK\x03\x04"):
        j = buf.find(sig, off+6)
        if j != -1: nexts.append(j)
    e = min(nexts)
    return e if e-off >= MIN else None

def end_tar(buf, off):
    # TAR archive - 512 byte blocks
    # Very heuristic approach
    pos = off + 512
    while pos < len(buf):
        if pos + 512 > len(buf): break
        # Look for next file header or end
        if buf[pos:pos+5] == b"ustar" or all(b == 0 for b in buf[pos:pos+512]):
            pos += 512
        else:
            break
    return pos if pos > off + MIN else None

def end_xml(buf, off):
    # XML/HTML - look for closing tag or next magic
    n = len(buf)
    nexts = [n]
    # Look for common XML/HTML endings
    for end_pattern in (b"</html>", b"</xml>", b"</root>", b"<?xml"):
        j = buf.find(end_pattern, off+5)
        if j != -1: 
            nexts.append(j + len(end_pattern))
    # Also look for next binary format
    for sig in (b"\x89PNG", b"RIFF", b"PK\x03\x04", b"MZ"):
        j = buf.find(sig, off+10)
        if j != -1: nexts.append(j)
    e = min(nexts)
    return e if e-off >= MIN else None

def end_font(buf, off):
    # Font files - various formats
    n = len(buf)
    nexts = [n]
    for sig in (b"\x00\x01\x00\x00", b"OTTO", b"wOFF", b"\x89PNG", b"PK\x03\x04"):
        j = buf.find(sig, off+4)
        if j != -1: nexts.append(j)
    e = min(nexts)
    return e if e-off >= MIN else None

MAGICS = [
    ("png",  b"\x89PNG\r\n\x1a\n", ".png", end_png,   valid_png),
    ("jpg",  b"\xff\xd8\xff",       ".jpg", end_jpeg,  valid_jpeg),
    ("gif",  b"GIF87a",             ".gif", end_gif,   None),
    ("gif",  b"GIF89a",             ".gif", end_gif,   None),
    ("zip",  b"PK\x03\x04",         ".zip", end_zip,   valid_zip),
    ("gzip", b"\x1f\x8b\x08",       ".gz",  end_gzip,  None),
    ("pdf",  b"%PDF-",              ".pdf", end_pdf,   None),
    ("bmp",  b"BM",                 ".bmp", end_bmp,   valid_bmp),
    ("ico",  b"\x00\x00\x01\x00",   ".ico", end_ico,   valid_ico),  # ICO signature
    ("mp3",  b"\xff\xfb",           ".mp3", end_mp3,   valid_mp3), # MP3 MPEG-1 Layer 3
    ("mp3",  b"\xff\xfa",           ".mp3", end_mp3,   valid_mp3), # MP3 MPEG-1 Layer 3 (alternative)
    ("mp3",  b"ID3",                ".mp3", end_mp3,   valid_mp3), # MP3 with ID3v2 tag
    ("ogg",  b"OggS",               ".ogg", end_ogg,   valid_ogg), # Ogg Vorbis/FLAC/etc
    ("flac", b"fLaC",               ".flac",end_flac,  None),      # FLAC audio
    ("wav",  b"RIFF",               ".wav", end_wav,   valid_wav), # Check for WAVE before WebP
    ("avi",  b"RIFF",               ".avi", end_avi,   None),      # AVI video (RIFF+AVI)
    ("webp", b"RIFF",               ".webp",end_riff_webp, None),
    # Archives and executables
    ("exe",  b"MZ",                 ".exe", end_exe,   None),      # PE/DOS executables
    ("dll",  b"MZ",                 ".dll", end_dll,   None),      # PE DLLs
    ("cab",  b"MSCF",               ".cab", end_cab,   None),      # Microsoft Cabinet
    ("rar",  b"Rar!\x1a\x07\x00",  ".rar", end_rar,   None),      # RAR archive
    ("7z",   b"7z\xbc\xaf\x27\x1c", ".7z", end_7z,    None),      # 7-Zip archive
    ("tar",  b"ustar\x00",          ".tar", end_tar,   None),      # TAR archive (at offset 257)
    # Documents and data
    ("xml",  b"<?xml",              ".xml", end_xml,   None),      # XML documents
    ("html", b"<html",              ".html",end_xml,   None),      # HTML documents
    ("html", b"<HTML",              ".html",end_xml,   None),      # HTML (uppercase)
    ("html", b"<!DOCTYPE",          ".html",end_xml,   None),      # HTML with DOCTYPE
    # Fonts
    ("ttf",  b"\x00\x01\x00\x00",   ".ttf", end_font,  valid_ttf),      # TrueType fonts
    ("otf",  b"OTTO",               ".otf", end_font,  valid_otf),      # OpenType fonts
    ("woff", b"wOFF",               ".woff",end_font,  None),      # Web fonts
    # Additional image formats
    ("tiff", b"II*\x00",            ".tiff",end_font,  None),      # TIFF (little endian)
    ("tiff", b"MM\x00*",            ".tiff",end_font,  None),      # TIFF (big endian)
]

def assemble_ico_from_pe_resources(output_dir):
    """Assemble proper ICO files from RT_ICON and RT_GROUP_ICON resources"""
    import glob
    import struct
    
    # Look for groupicon and icon files
    groupicon_files = glob.glob(str(output_dir / "**/groupicon_*.bin"), recursive=True)
    if not groupicon_files:
        return []
    
    assembled_icos = []
    
    for groupicon_file in groupicon_files:
        try:
            groupicon_path = pathlib.Path(groupicon_file)
            groupicon_data = groupicon_path.read_bytes()
            
            if len(groupicon_data) < 6:
                continue
                
            # Parse RT_GROUP_ICON structure
            # WORD idReserved (should be 0)
            # WORD idType (should be 1 for ICO)
            # WORD idCount (number of images)
            reserved, img_type, count = struct.unpack("<HHH", groupicon_data[:6])
            
            if img_type != 1 or count == 0 or count > 64:
                continue
                
            # Each directory entry is 14 bytes in RT_GROUP_ICON vs 16 in ICO
            entries = []
            offset = 6
            
            for i in range(count):
                if offset + 14 > len(groupicon_data):
                    break
                    
                # Parse RT_GROUP_ICON directory entry (14 bytes)
                # Format: BYTE width, BYTE height, BYTE colors, BYTE reserved, WORD planes, WORD bpp, DWORD size, WORD icon_id
                entry_data = groupicon_data[offset:offset + 14]
                width, height, colors, reserved2, planes, bpp, size, icon_id = struct.unpack("<BBBBHHIH", entry_data)
                
                # Find corresponding RT_ICON file
                icon_filename = groupicon_path.parent / f"icon_{icon_id:04x}.bin"
                if not icon_filename.exists():
                    offset += 14
                    continue
                    
                icon_data = icon_filename.read_bytes()
                if len(icon_data) != size:
                    # Try to find any icon file that matches the size
                    for potential_icon in groupicon_path.parent.glob("icon_*.bin"):
                        pot_data = potential_icon.read_bytes()
                        if len(pot_data) == size:
                            icon_data = pot_data
                            break
                
                entries.append({
                    'width': width if width != 0 else 256,
                    'height': height if height != 0 else 256,
                    'colors': colors,
                    'reserved': reserved2,
                    'planes': planes,
                    'bpp': bpp,
                    'size': len(icon_data),
                    'data': icon_data
                })
                
                offset += 14
            
            if not entries:
                continue
                
            # Build proper ICO file
            ico_data = bytearray()
            
            # ICO header
            ico_data.extend(struct.pack("<HHH", 0, 1, len(entries)))
            
            # Calculate data offsets
            data_offset = 6 + len(entries) * 16  # Header + directory entries
            
            # Write directory entries
            for entry in entries:
                ico_data.extend(struct.pack("<BBBBHHII", 
                    entry['width'] if entry['width'] < 256 else 0,
                    entry['height'] if entry['height'] < 256 else 0,
                    entry['colors'],
                    entry['reserved'],
                    entry['planes'],
                    entry['bpp'],
                    entry['size'],
                    data_offset
                ))
                data_offset += entry['size']
            
            # Write image data
            for entry in entries:
                ico_data.extend(entry['data'])
            
            # Save assembled ICO
            base_name = groupicon_path.stem.replace('groupicon_', 'assembled_ico_')
            ico_filename = groupicon_path.parent / f"{base_name}.ico"
            ico_filename.write_bytes(ico_data)
            
            assembled_icos.append({
                'file': str(ico_filename),
                'size': len(ico_data),
                'entries': len(entries),
                'source_groupicon': str(groupicon_path)
            })
            
        except Exception as e:
            print(f"Failed to assemble ICO from {groupicon_file}: {e}")
            continue
    
    return assembled_icos

def repair_asset(data, asset_type, offset):
    """Attempt to repair corrupted assets"""
    if asset_type == "bmp":
        return repair_bmp(data)
    elif asset_type == "webp":
        return repair_webp(data)
    elif asset_type == "png":
        return repair_png(data)
    elif asset_type == "jpg":
        return repair_jpeg(data)
    elif asset_type == "ico":
        return repair_ico(data)
    elif asset_type == "wav":
        return repair_wav(data)
    return data

def repair_bmp(data):
    """Repair BMP files with corrupted headers"""
    if len(data) < 54: return data
    try:
        # Fix file size in header if it's wrong
        actual_size = len(data)
        data = bytearray(data)
        data[2:6] = struct.pack("<I", actual_size)
        
        # Ensure reserved fields are zero
        data[6:10] = b"\x00\x00\x00\x00"
        
        # Fix data offset if reasonable
        offset = struct.unpack("<I", data[10:14])[0]
        if offset < 54 or offset >= len(data):
            data[10:14] = struct.pack("<I", 54)  # Standard header size
            
        return bytes(data)
    except:
        return data

def repair_webp(data):
    """Repair WebP files with corrupted RIFF headers"""
    if len(data) < 12: return data
    try:
        data = bytearray(data)
        # Fix RIFF size field
        riff_size = len(data) - 8
        data[4:8] = struct.pack("<I", riff_size)
        return bytes(data)
    except:
        return data

def repair_png(data):
    """Repair PNG files with missing or corrupted IEND"""
    if len(data) < 33: return data
    try:
        if not data.endswith(b"IEND\xaeB`\x82"):
            # Append IEND chunk if missing
            data = data + b"\x00\x00\x00\x00IEND\xaeB`\x82"
        return data
    except:
        return data

def repair_jpeg(data):
    """Repair JPEG files with missing EOI marker"""
    if len(data) < 10: return data
    try:
        if not data.endswith(b"\xff\xd9"):
            # Append EOI marker if missing
            data = data + b"\xff\xd9"
        return data
    except:
        return data

def repair_ico(data):
    """Repair ICO files with corrupted headers"""
    if len(data) < 6: return data
    try:
        data = bytearray(data)
        # Ensure reserved field is 0
        data[0:2] = b"\x00\x00"
        # Ensure type is 1 (ICO)
        data[2:4] = b"\x01\x00"
        return bytes(data)
    except:
        return data

def repair_wav(data):
    """Repair WAV files with corrupted RIFF headers"""
    if len(data) < 12: return data
    try:
        data = bytearray(data)
        # Fix RIFF size field
        riff_size = len(data) - 8
        data[4:8] = struct.pack("<I", riff_size)
        return bytes(data)
    except:
        return data

def dump_strings(buf, out_path, min_len=4):
    asc = re.findall(rb"[ -~]{%d,}" % min_len, buf)
    u16 = re.findall((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len), buf)
    with open(out_path, "w", encoding="utf-8", errors="ignore") as w:
        w.write("# ASCII strings\n")
        for s in asc:
            try: w.write(s.decode("ascii") + "\n")
            except: pass
        w.write("\n# UTF-16LE strings\n")
        for s in u16:
            try: w.write(s.decode("utf-16le") + "\n")
            except: pass

def main():
    if len(sys.argv) < 3:
        print("Usage: carve_assets.py <binary> <out_dir>")
        sys.exit(1)
    bin_path, out_dir = sys.argv[1], sys.argv[2]
    data = pathlib.Path(bin_path).read_bytes()
    out = pathlib.Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    carved = out / "carved"; carved.mkdir(exist_ok=True)
    strings_path = out / "strings.txt"
    index = []
    bad = []

    dump_strings(data, strings_path)

    taken = [False]*len(data)

    for name, sig, ext, finder, validator in MAGICS:
        for off in find_all(data, sig):
            if any(taken[off:off+len(sig)]):  # overlapping start
                continue
            end = finder(data, off)
            if not end or end - off < MIN:
                # Try to extract small/corrupted assets anyway with minimal size
                if end and end > off:
                    # Very small asset - extract it anyway
                    chunk = data[off:end]
                    tiny_fn = f"{name}_{off:08x}_tiny{ext}"
                    try:
                        (carved / tiny_fn).write_bytes(chunk)
                        index.append({"type": name, "offset": off, "end": end, "size": len(chunk), 
                                    "file": f"carved/{tiny_fn}", "note": "tiny_extraction"})
                        continue
                    except:
                        pass
                bad.append({"type": name, "offset": off, "reason": "no_end_or_too_small"})
                continue
            chunk = data[off:end]
            
            # Try to repair the asset before validation
            repaired_chunk = repair_asset(chunk, name, off)
            
            if validator and not validator(repaired_chunk):
                # If repair didn't work, try original chunk
                if validator(chunk):
                    repaired_chunk = chunk
                else:
                    # Extract anyway for manual inspection
                    bad_fn = f"{name}_{off:08x}_corrupted{ext}"
                    try:
                        (carved / bad_fn).write_bytes(repaired_chunk)
                        index.append({"type": name, "offset": off, "end": end, "size": len(repaired_chunk), 
                                    "file": f"carved/{bad_fn}", "note": "extracted_despite_corruption"})
                    except:
                        pass
                    bad.append({"type": name, "offset": off, "reason": "validator_failed"})
                    continue
            # More permissive overlap handling - extract overlapping assets with suffixes
            overlap_size = sum(taken[off:end])
            if overlap_size > min(128, (end-off) * 0.2):  # Allow up to 128 bytes or 20% overlap
                # Try to extract anyway with overlap suffix
                overlap_suffix = f"_overlap_{overlap_size}"
                fn_overlap = f"{name}_{off:08x}{overlap_suffix}{ext}"
                try:
                    (carved / fn_overlap).write_bytes(repaired_chunk)
                    index.append({"type": name, "offset": off, "end": end, "size": len(repaired_chunk), 
                                "file": f"carved/{fn_overlap}", "note": "overlapping_extraction"})
                    continue
                except:
                    bad.append({"type": name, "offset": off, "reason": f"overlap_{overlap_size}_bytes"})
                    continue
            for i in range(off, end):
                taken[i] = True
            fn = f"{name}_{off:08x}{ext}"
            (carved / fn).write_bytes(repaired_chunk)
            repair_note = "repaired" if repaired_chunk != chunk else "original"
            index.append({"type": name, "offset": off, "end": end, "size": len(repaired_chunk), 
                        "file": f"carved/{fn}", "note": repair_note})

    # Try to assemble ICO files from PE resources
    assembled_icos = assemble_ico_from_pe_resources(out)
    if assembled_icos:
        print(f"[✓] Assembled {len(assembled_icos)} ICO files from PE resources")
        for ico_info in assembled_icos:
            index.append({
                "type": "ico_assembled", 
                "offset": 0, 
                "end": ico_info['size'], 
                "size": ico_info['size'],
                "file": ico_info['file'], 
                "note": f"assembled_from_pe_resources_{ico_info['entries']}_entries",
                "source": ico_info['source_groupicon']
            })

    (out / "assets_index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    (out / "assets_rejected.json").write_text(json.dumps(bad, indent=2), encoding="utf-8")
    print(f"[✓] Strings → {strings_path}")
    print(f"[✓] Kept {len(index)} assets, rejected {len(bad)} → see assets_rejected.json")
    print(f"[✓] Output → {carved}")

if __name__ == "__main__":
    main()

