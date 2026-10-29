import uuid
import hashlib
import math
import mimetypes
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from app.schemas import FileAnalysisResponse
from app.config import settings

# Max file size: 15MB for static analysis
MAX_FILE_SIZE = 15 * 1024 * 1024

# Built-in signatures: only the EICAR anti-virus test file, which is public and harmless. Real malware hashes are not
# bundled because nobody here can vouch for them; load your own feed instead (see load_hash_feed).
BUILTIN_SIGNATURES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "threat_name": "EICAR-Standard-AV-Test-File", "family": "Anti-virus test pattern", "severity": "High"},
    "44d88612fea8a8f36de82e1278abb02f": {
        "threat_name": "EICAR-Standard-AV-Test-File", "family": "Anti-virus test pattern", "severity": "High"},
}


def load_hash_feed(path: str) -> Dict[str, Dict[str, str]]:
    """Reads a plain-text hash list (one md5/sha256 per line, optional ',name' after it; '#' starts a comment), such as an
    export from MalwareBazaar or your EDR. Every entry is treated as known-malicious."""
    out: Dict[str, Dict[str, str]] = {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                digest, _, name = line.partition(",")
                digest = digest.strip().lower()
                if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{64}", digest):
                    out[digest] = {"threat_name": name.strip() or "Listed in the organisation's hash feed",
                                   "family": "Hash feed", "severity": "High"}
    except OSError:
        pass
    return out


SUSPICIOUS_STRING_PATTERNS = [
    (r"powershell(\.exe)?\s+(-\w+\s+)*-(enc|encodedcommand|e\b)|powershell(\.exe)?[^\n]{0,80}(executionpolicy\s+bypass|windowstyle\s+hidden|-nop\b)", "Obfuscated or hidden PowerShell execution", 50),
    (r"(cmd(\.exe)?\s+/c\s+(curl|wget|certutil|bitsadmin))|(certutil(\.exe)?\s+-urlcache)|(bitsadmin\s+/transfer)", "Living-off-the-land download command", 45),
    (r"WScript\.Shell|Shell\.Application|eval\(base64_decode|FromBase64String\([^)]*\)[\s\S]{0,60}(Invoke-Expression|iex\b)", "Script host or dynamic code evaluation", 25),
    (r"YOUR_FILES_ARE_ENCRYPTED|your (files|data|documents) (have been|are|were) (encrypted|locked)|HOW_TO_(DECRYPT|RECOVER)|decrypt_notes|restore_your_data|pay (the )?ransom", "Ransom-note language", 55),
    (r"mimikatz|sekurlsa::|lsass\.dmp|MiniDumpWriteDump[\s\S]{0,200}lsass", "Credential-dumping signature", 55),
    (r"(\\x90){6,}|(0x90[\s,]+){6,}", "NOP-sled shellcode pattern", 30),
    (r"Auto_?Open|Document_?Open|Workbook_?Open[\s\S]{0,400}(Shell|CreateObject|powershell)", "Auto-run macro that launches a program", 50),
]
# Injection needs all three steps: allocate in a process, write into it, start a thread there. Any one of these alone is
# ordinary in legitimate software, so they are checked as plain substrings (a lookahead regex is quadratic on big files).
INJECTION_STEPS = [("virtualalloc", "ntallocatevirtualmemory"), ("writeprocessmemory", "ntwritevirtualmemory"),
                   ("createremotethread", "ntcreatethreadex", "queueuserapc", "ntunmapviewofsection")]
EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".dll", ".com", ".msi", ".pif"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".hta", ".js", ".jse", ".wsf"}
# Formats that are compressed or encrypted by design: a high entropy value says nothing about them.
COMPRESSED_MAGIC = [(b"PK\x03\x04", "ZIP or Office container"), (b"%PDF", "PDF"), (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
                    (b"GIF8", "GIF image"), (b"\x1f\x8b", "gzip"), (b"7z\xbc\xaf", "7-Zip"), (b"Rar!", "RAR"), (b"BZh", "bzip2"),
                    (b"\xfd7zXZ", "xz"), (b"RIFF", "RIFF media"), (b"OggS", "Ogg media"), (b"ID3", "MP3 audio"), (b"\x00\x00\x00\x18ftyp", "MP4 media"),
                    (b"\x00\x00\x00\x20ftyp", "MP4 media"), (b"wOFF", "web font"), (b"wOF2", "web font")]
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
NON_EXECUTABLE_EXTENSIONS = {".pdf", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".mp3", ".mp4", ".zip"}

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Shannon Entropy: Returns a value between 0.0 and 8.0.
    Values > 7.2 usually indicate heavy encryption or executable packing.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def check_pe_header(data: bytes) -> Tuple[bool, Dict[str, Any]]:
    """
    Safe static inspection for Windows PE (Portable Executable) format without execution.
    """
    if len(data) < 64:
        return False, {}
    if data[:2] != b"MZ":
        return False, {}
    
    # Read e_lfanew at offset 0x3C
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x40], byteorder="little")
        if e_lfanew + 4 <= len(data) and data[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
            # Valid PE Signature
            machine_bytes = data[e_lfanew+4:e_lfanew+6]
            machine_arch = "x64" if machine_bytes == b"\x64\x86" else "x86" if machine_bytes == b"\x4c\x01" else "Unknown"
            num_sections = int.from_bytes(data[e_lfanew+6:e_lfanew+8], byteorder="little")
            return True, {
                "format": "Windows Portable Executable (PE)",
                "architecture": machine_arch,
                "sections_count": num_sections,
                "is_executable": True
            }
    except Exception:
        pass
    return True, {"format": "DOS MZ Header", "is_executable": True}

_feed_cache: Dict[str, Any] = {"path": None, "mtime": None, "data": {}}


def _hash_feed() -> Dict[str, Dict[str, str]]:
    path = settings.FILE_HASH_FEED_PATH
    if not path:
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _feed_cache["path"] != path or _feed_cache["mtime"] != mtime:
        _feed_cache.update(path=path, mtime=mtime, data=load_hash_feed(path))
    return _feed_cache["data"]


class FileAnalyzer:
    def analyze_file_bytes(self, filename: str, content: bytes) -> FileAnalysisResponse:
        filesize = len(content)
        if filesize > MAX_FILE_SIZE:
            raise ValueError(f"File size exceeds maximum static analysis threshold of {MAX_FILE_SIZE // (1024*1024)}MB.")

        # 1. Cryptographic Hashes
        sha256 = hashlib.sha256(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()

        # 2. Entropy Analysis
        entropy = calculate_shannon_entropy(content)

        # 3. MIME type detection
        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or "application/octet-stream"

        # 4. Format from magic bytes (the extension is only a claim)
        is_pe, pe_info = check_pe_header(content)
        container = next((name for magic, name in COMPRESSED_MAGIC if content.startswith(magic)), None)
        is_ole = content.startswith(OLE_MAGIC)
        ext = os.path.splitext(filename)[1].lower()

        suspicious_patterns: List[str] = []
        score = 5

        # 5. Static string patterns, on at most the first 4 MB
        text_sample = content[:4 * 1024 * 1024].decode("utf-8", errors="ignore")
        for pattern, label, weight in SUSPICIOUS_STRING_PATTERNS:
            if re.search(pattern, text_sample, re.IGNORECASE):
                suspicious_patterns.append(f"{label} (Risk +{weight})")
                score += weight

        lowered = text_sample.lower()
        if all(any(api in lowered for api in step) for step in INJECTION_STEPS):
            suspicious_patterns.append("Process-injection API combination (Risk +55)")
            score += 55

        # 6. Format versus claimed type
        if is_pe and ext in NON_EXECUTABLE_EXTENSIONS:
            score += 55
            suspicious_patterns.append(f"Windows executable disguised with a '{ext}' extension (Risk +55)")
        if b"vbaProject.bin" in content[:2_000_000] or (is_ole and re.search(rb"VBA|_VBA_PROJECT", content[:2_000_000])):
            score += 30
            suspicious_patterns.append("Office document contains VBA macros (Risk +30)")
        if ext in EXECUTABLE_EXTENSIONS and is_pe:
            score += 10
            suspicious_patterns.append(f"Windows executable ('{ext}'): not harmful by itself, check where it came from (Risk +10)")
        elif ext in SCRIPT_EXTENSIONS:
            score += 10
            suspicious_patterns.append(f"Script file ('{ext}'): can run commands when opened (Risk +10)")

        # 7. Entropy: meaningful for executables and unknown blobs, not for formats that are compressed by design
        if container or is_ole:
            entropy_note = f"{entropy}/8.0 is normal for {container or 'an Office document'}"
        elif entropy >= 7.3 and (is_pe or ext not in NON_EXECUTABLE_EXTENSIONS):
            suspicious_patterns.append(f"High byte entropy ({entropy}/8.0): encrypted or packed content (Risk +25)")
            score += 25
            entropy_note = "high"
        elif entropy >= 6.8 and is_pe:
            suspicious_patterns.append(f"Elevated byte entropy ({entropy}/8.0) in an executable: possibly packed (Risk +15)")
            score += 15
            entropy_note = "elevated"
        else:
            entropy_note = "ordinary"

        # 8. Hash lookup: built-in test signature plus the organisation's own feed
        signatures = {**BUILTIN_SIGNATURES, **_hash_feed()}
        reputation_result = {
            "service": "Local signature list" + (" + organisation hash feed" if settings.FILE_HASH_FEED_PATH else ""),
            "status": "Queried",
            "match_found": False,
            "entries": len(signatures),
            "external_api_configured": bool(settings.VIRUSTOTAL_API_KEY),
        }
        matched_signature = signatures.get(sha256) or signatures.get(md5)
        if matched_signature:
            score = max(score, 90)
            reputation_result.update(match_found=True, threat_name=matched_signature["threat_name"],
                                     family=matched_signature["family"], known_severity=matched_signature["severity"])
            suspicious_patterns.append(f"Known threat match: {matched_signature['threat_name']} ({matched_signature['family']})")
        else:
            reputation_result["notice"] = (
                f"No match among {len(signatures)} local signature(s). The list holds only the EICAR test file unless FILE_HASH_FEED_PATH points to a hash feed. "
                "No online reputation lookup was made."
            )

        final_score = min(max(score, 2), 99)
        risk_category = self._score_to_category(final_score)

        explanation = (
            f"Static file analysis completed for '{filename}'. Evaluated as {risk_category} Risk (Score: {final_score}/100). "
            f"Entropy: {entropy} / 8.0 ({entropy_note}). Detected {len(suspicious_patterns)} suspicious signal(s)."
        )

        precautions = [
            "Do not execute or unpack untrusted artifacts on endpoints or corporate hosts.",
            "Run dynamic behavioral observation inside an air-gapped sandbox VM if full analysis is required.",
            "Cross-verify file SHA-256 against enterprise EDR telemetry across all managed fleet systems."
        ]

        if final_score >= 60:
            precautions.insert(0, f"Submit hash {sha256[:16]}... to corporate perimeter firewall and endpoint AV blacklist immediately.")

        return FileAnalysisResponse(
            analysis_id=f"TA-FILE-{uuid.uuid4().hex[:12].upper()}",
            filename=filename,
            filesize_bytes=filesize,
            mime_type=mime_type,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            entropy=entropy,
            risk_score=final_score,
            risk_category=risk_category,
            detection_engine="Static analysis: hashes, file format, entropy and byte patterns",
            is_pe_executable=is_pe,
            suspicious_patterns=suspicious_patterns,
            metadata={
                "size_human": f"{round(filesize / 1024, 2)} KB",
                "pe_details": pe_info,
                "extension": ext
            },
            reputation_lookup=reputation_result,
            explanation=explanation,
            recommended_precautions=precautions,
            disclaimer="CRITICAL NOTICE: Static analysis alone cannot guarantee that a file is safe or malicious. Advanced modern malware frequently leverages in-memory staging, sleep obfuscation, or runtime decryption to evade static file inspection."
        )

    def _score_to_category(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 35:
            return "Medium"
        return "Low"

file_analyzer = FileAnalyzer()
