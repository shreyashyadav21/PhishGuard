import hashlib
import mimetypes
import os
import re
from typing import Dict, Any, List, Optional

DANGEROUS_EXTENSIONS = {
    # Direct executables & scripts
    ".exe": ("Critical", "Windows Executable Binary", 35),
    ".scr": ("Critical", "Windows Screensaver / Executable Dropper", 35),
    ".bat": ("Critical", "Windows Batch Script", 30),
    ".cmd": ("Critical", "Windows Command Script", 30),
    ".vbs": ("Critical", "VBScript Payload", 35),
    ".vbe": ("Critical", "Encoded VBScript Payload", 35),
    ".js":  ("Critical", "JavaScript Script File", 30),
    ".jse": ("Critical", "Encoded JavaScript Payload", 30),
    ".wsf": ("Critical", "Windows Script File", 30),
    ".hta": ("Critical", "HTML Application Executable", 35),
    ".pif": ("Critical", "Program Information File (Legacy Executable)", 35),
    ".cpl": ("Critical", "Control Panel Extension Binary", 35),
    ".msi": ("High", "Windows Installer Package", 25),
    ".msp": ("High", "Windows Installer Patch", 25),
    ".iso": ("High", "Disk Image Container (Container Mark-of-the-Web bypass)", 30),
    ".img": ("High", "Disk Image Container", 30),
    ".reg": ("High", "Registry Modification File", 25),
    ".ps1": ("High", "PowerShell Script", 30),
    # Macro-enabled Office documents
    ".docm": ("High", "Macro-Enabled Microsoft Word Document", 25),
    ".xlsm": ("High", "Macro-Enabled Microsoft Excel Spreadsheet", 25),
    ".pptm": ("High", "Macro-Enabled Microsoft PowerPoint Presentation", 25),
    ".dotm": ("High", "Macro-Enabled Word Template", 25),
}

# Magic byte signatures
MAGIC_SIGNATURES = {
    b"MZ": ("PE Executable", [".exe", ".dll", ".scr", ".sys", ".cpl"]),
    b"PK\x03\x04": ("ZIP / OpenXML Archive", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    b"Rar!\x1a\x07": ("RAR Archive", [".rar"]),
    b"7z\xbc\xaf\x27\x1c": ("7-Zip Archive", [".7z"]),
    b"%PDF-": ("PDF Document", [".pdf"]),
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": ("Legacy Microsoft Compound File (OLE/VBA)", [".doc", ".xls", ".ppt"]),
}

def calculate_sha256(content_bytes: bytes) -> str:
    """Calculates SHA-256 hash of file content."""
    return hashlib.sha256(content_bytes).hexdigest()

def analyze_attachment(
    filename: str,
    content_bytes: Optional[bytes] = None,
    file_size: int = 0,
    declared_mime: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs safe static inspection of email attachments without code execution.
    Inspects filename, double extensions, hashes, MIME types, and magic bytes.
    """
    clean_name = os.path.basename(filename).strip()
    _, ext = os.path.splitext(clean_name.lower())

    if content_bytes:
        actual_size = len(content_bytes)
        sha256 = calculate_sha256(content_bytes)
        header_sample = content_bytes[:32]
    else:
        actual_size = file_size
        sha256 = calculate_sha256(clean_name.encode())
        header_sample = b""

    inferred_mime, _ = mimetypes.guess_type(clean_name)
    effective_mime = declared_mime or inferred_mime or "application/octet-stream"

    reasons: List[str] = []
    threat_score = 0
    is_dangerous = False

    # 1. Double Extension Trick (e.g., 'invoice.pdf.exe', 'photo.jpg.vbs')
    # Matches patterns where a deceptive benign extension is followed by an executable extension
    double_ext_match = re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.([a-zA-Z0-9]+)$", clean_name.lower())
    if double_ext_match:
        hidden_ext = f".{double_ext_match.group(2)}"
        reasons.append(
            f"Double extension deception detected ('{clean_name}'). Attacker disguised executable '{hidden_ext}' as '{double_ext_match.group(1)}'."
        )
        threat_score += 35
        is_dangerous = True

    # 2. Dangerous Executable or Script Extension
    if ext in DANGEROUS_EXTENSIONS:
        sev, desc, pts = DANGEROUS_EXTENSIONS[ext]
        reasons.append(f"High-risk extension '{ext}': {desc}.")
        threat_score += pts
        is_dangerous = True

    # 3. Magic Bytes Inspection vs Declared Extension
    if header_sample:
        detected_sig = None
        for sig, (sig_name, valid_exts) in MAGIC_SIGNATURES.items():
            if header_sample.startswith(sig):
                detected_sig = (sig_name, valid_exts)
                break

        if detected_sig:
            sig_name, valid_exts = detected_sig
            # Mismatch: File named as harmless image or PDF but contains Windows Executable (MZ)
            if header_sample.startswith(b"MZ") and ext not in valid_exts:
                reasons.append(
                    f"Severe file format spoofing! File is named '{clean_name}' ({ext}) but header contains 'MZ' Windows Portable Executable binary signature."
                )
                threat_score += 40
                is_dangerous = True

    # 4. Oversized or Suspicious Archive
    if ext in [".zip", ".rar", ".7z", ".tar", ".gz"]:
        if actual_size > 50 * 1024 * 1024:  # > 50MB
            reasons.append(f"Unusually large archive ({round(actual_size / (1024*1024), 1)} MB), potential archive bomb.")
            threat_score += 15
        else:
            reasons.append(f"Compressed archive container '{ext}'. Requires sandboxed decompression to inspect contents.")
            threat_score += 5

    # Cap score at 100
    final_score = min(100, threat_score)

    return {
        "filename": clean_name,
        "extension": ext,
        "file_size": actual_size,
        "mime_type": effective_mime,
        "sha256_hash": sha256,
        "is_dangerous": is_dangerous,
        "threat_score": final_score,
        "severity": "Critical" if final_score >= 70 else ("High" if final_score >= 40 else ("Medium" if final_score >= 20 else "Low")),
        "threat_reasons": reasons,
        "safe_to_open": not is_dangerous and final_score < 20
    }

