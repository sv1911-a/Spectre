"""Native file triage primitives.

First-pass file analysis without shelling out to external tools.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from spectre.core.artifacts import extract_artifacts
from spectre.sources.github.adapter import scan_text_for_secrets


@dataclass(frozen=True, slots=True)
class Signature:
    name: str
    artifact_type: str
    offset: int
    magic: bytes
    mime: str = "application/octet-stream"
    extensions: tuple[str, ...] = ()


SIGNATURES: tuple[Signature, ...] = (
    Signature("PNG image", "image", 0, b"\x89PNG\r\n\x1a\n", "image/png", ("png",)),
    Signature("JPEG image", "image", 0, b"\xff\xd8\xff", "image/jpeg", ("jpg", "jpeg")),
    Signature("GIF image", "image", 0, b"GIF8", "image/gif", ("gif",)),
    Signature("PDF document", "document", 0, b"%PDF-", "application/pdf", ("pdf",)),
    Signature("ZIP archive", "archive", 0, b"PK\x03\x04", "application/zip", ("zip", "jar", "docx", "xlsx", "pptx")),
    Signature("Empty ZIP archive", "archive", 0, b"PK\x05\x06", "application/zip", ("zip",)),
    Signature("Spanned ZIP archive", "archive", 0, b"PK\x07\x08", "application/zip", ("zip",)),
    Signature("Gzip archive", "archive", 0, b"\x1f\x8b\x08", "application/gzip", ("gz",)),
    Signature("Bzip2 archive", "archive", 0, b"BZh", "application/x-bzip2", ("bz2",)),
    Signature("XZ archive", "archive", 0, b"\xfd7zXZ\x00", "application/x-xz", ("xz",)),
    Signature("7-Zip archive", "archive", 0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ("7z",)),
    Signature("RAR archive v4", "archive", 0, b"Rar!\x1a\x07\x00", "application/vnd.rar", ("rar",)),
    Signature("RAR archive v5", "archive", 0, b"Rar!\x1a\x07\x01\x00", "application/vnd.rar", ("rar",)),
    Signature("ELF binary", "binary", 0, b"\x7fELF", "application/x-elf", ("elf", "so")),
    Signature("DOS/PE executable", "binary", 0, b"MZ", "application/vnd.microsoft.portable-executable", ("exe", "dll", "sys")),
    Signature("Mach-O 32-bit", "binary", 0, b"\xfe\xed\xfa\xce", "application/x-mach-binary", ("macho",)),
    Signature("Mach-O 64-bit", "binary", 0, b"\xfe\xed\xfa\xcf", "application/x-mach-binary", ("macho",)),
    Signature("Mach-O Universal", "binary", 0, b"\xca\xfe\xba\xbe", "application/x-mach-binary", ("macho",)),
    Signature("SQLite database", "document", 0, b"SQLite format 3\x00", "application/vnd.sqlite3", ("sqlite", "db")),
    Signature("Windows Registry hive", "document", 0, b"regf", "application/x-ms-registry", ("dat",)),
)

INTERESTING_FILENAMES = re.compile(r"(?i)(password|passwd|secret|token|key|credential|config|backup|dump|wallet|id_rsa|\.env)")
SUSPICIOUS_STRINGS = re.compile(r"(?i)(powershell|cmd\.exe|/bin/sh|curl\s|wget\s|eval\(|base64\s+-d|frombase64string|createprocess|virtualalloc|writeprocessmemory|loadlibrary|getprocaddress)")


def analyze_file(path: str | Path, max_strings: int = 300) -> dict[str, Any]:
    file_path = Path(path)
    data = file_path.read_bytes()
    signatures = detect_signatures(data)
    strings = extract_strings(data, max_strings=max_strings)
    joined_strings = "\n".join(strings)
    artifacts = [
        {
            "id": artifact.id,
            "type": artifact.type.value,
            "value": artifact.value,
            "confidence": artifact.confidence,
            "metadata": artifact.metadata,
        }
        for artifact in extract_artifacts(joined_strings)
    ]
    embedded = detect_embedded_signatures(data)
    return {
        "path": str(file_path),
        "name": file_path.name,
        "size": len(data),
        "hashes": file_hashes(data),
        "entropy": shannon_entropy(data),
        "signatures": signatures,
        "extension": file_path.suffix.lower().lstrip("."),
        "extension_matches_signature": extension_matches(file_path, signatures),
        "strings": strings,
        "iocs": _summarize_iocs(artifacts),
        "embedded_signatures": embedded,
        "embedded_archives": [item for item in embedded if item.get("artifact_type") == "archive"],
        "embedded_executables": [item for item in embedded if item.get("artifact_type") == "binary"],
        "potential_secrets": scan_text_for_secrets(joined_strings, str(file_path), max_findings=25),
        "language_hints": language_hints(file_path, strings),
        "interesting_filename": bool(INTERESTING_FILENAMES.search(file_path.name)),
        "suspicious_patterns": suspicious_patterns(strings),
        "binary_info": binary_triage(data),
    }


def detect_signatures(data: bytes) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for signature in SIGNATURES:
        if len(data) >= signature.offset + len(signature.magic) and data[signature.offset : signature.offset + len(signature.magic)] == signature.magic:
            matches.append(_signature_dict(signature, signature.offset))
    return matches


def detect_embedded_signatures(data: bytes, limit: int = 40) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for signature in SIGNATURES:
        start = 1 if signature.offset == 0 else 0
        offset = data.find(signature.magic, start)
        while offset != -1 and len(matches) < limit:
            matches.append(_signature_dict(signature, offset))
            offset = data.find(signature.magic, offset + 1)
    return sorted(matches, key=lambda item: item["offset"])


def _signature_dict(signature: Signature, offset: int) -> dict[str, Any]:
    return {
        "name": signature.name,
        "artifact_type": signature.artifact_type,
        "offset": offset,
        "magic_hex": signature.magic.hex(),
        "mime": signature.mime,
        "extensions": list(signature.extensions),
    }


def extension_matches(path: Path, signatures: list[dict[str, Any]]) -> bool | None:
    if not signatures:
        return None
    extension = path.suffix.lower().lstrip(".")
    if not extension:
        return None
    return any(extension in signature.get("extensions", []) for signature in signatures)


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic identifier
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic identifier
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1
    entropy = 0.0
    for count in frequencies:
        if count:
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def extract_strings(data: bytes, min_length: int = 4, max_strings: int = 300) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> bool:
        value = value.strip("\x00")
        if len(value) >= min_length and value not in seen:
            seen.add(value)
            strings.append(value)
        return len(strings) >= max_strings

    current: bytearray = bytearray()
    for byte in data:
        if 32 <= byte <= 126 or byte in {9}:
            current.append(byte)
        else:
            if add(current.decode("ascii", errors="replace")):
                return strings
            current = bytearray()
    if add(current.decode("ascii", errors="replace")):
        return strings

    # UTF-16LE and UTF-16BE passes.
    for endian in ("little", "big"):
        current_chars: list[str] = []
        for index in range(0, len(data) - 1, 2):
            code = int.from_bytes(data[index : index + 2], endian)
            if 32 <= code <= 126 or code == 9:
                current_chars.append(chr(code))
            else:
                if add("".join(current_chars)):
                    return strings
                current_chars = []
        if add("".join(current_chars)):
            return strings
    return strings[:max_strings]


def _summarize_iocs(artifacts: list[dict[str, Any]]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for artifact in artifacts:
        output.setdefault(artifact["type"], [])
        value = artifact.get("value")
        if value and value not in output[artifact["type"]]:
            output[artifact["type"]].append(value)
    return {key: values[:50] for key, values in sorted(output.items())}


def suspicious_patterns(strings: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for value in strings:
        match = SUSPICIOUS_STRINGS.search(value)
        if match:
            findings.append({"pattern": match.group(0), "string": value[:180]})
            if len(findings) >= 20:
                break
    return findings


def language_hints(path: Path, strings: list[str]) -> list[str]:
    hints: set[str] = set()
    suffix = path.suffix.lower()
    suffix_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".php": "PHP",
        ".rb": "Ruby",
        ".go": "Go",
        ".rs": "Rust",
        ".java": "Java",
        ".ps1": "PowerShell",
        ".sh": "Shell",
        ".json": "JSON",
        ".xml": "XML",
        ".sql": "SQL",
        ".yml": "YAML",
        ".yaml": "YAML",
    }
    if suffix in suffix_map:
        hints.add(suffix_map[suffix])
    sample = "\n".join(strings[:80]).lower()
    indicators = {
        "Python": ["import ", "def ", "__main__"],
        "JavaScript": ["function(", "const ", "=>", "require("],
        "PowerShell": ["powershell", "get-process", "invoke-"],
        "Shell": ["#!/bin/sh", "#!/bin/bash"],
        "SQL": ["select ", "insert into", "update ", " from "],
        "PE/.NET": ["mscoree.dll", ".netframework", "system.runtime"],
    }
    for name, needles in indicators.items():
        if any(needle in sample for needle in needles):
            hints.add(name)
    return sorted(hints)


def binary_triage(data: bytes) -> dict[str, Any]:
    if data.startswith(b"\x7fELF"):
        return _elf_triage(data)
    if data.startswith(b"MZ"):
        return _pe_triage(data)
    return {}


def _elf_triage(data: bytes) -> dict[str, Any]:
    if len(data) < 0x40:
        return {"format": "ELF", "error": "truncated header"}
    cls = data[4]
    endian = "little" if data[5] == 1 else "big"
    arch_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS"}
    machine = int.from_bytes(data[18:20], endian)
    elf_type = int.from_bytes(data[16:18], endian)
    return {
        "format": "ELF",
        "architecture": arch_map.get(machine, f"machine_{machine}"),
        "class": "64-bit" if cls == 2 else "32-bit" if cls == 1 else "unknown",
        "pie": elf_type == 3,
        "protections": {"pie": elf_type == 3, "nx": None, "relro": None},
    }


def _pe_triage(data: bytes) -> dict[str, Any]:
    if len(data) < 0x40:
        return {"format": "PE", "error": "truncated DOS header"}
    pe_offset = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return {"format": "MZ", "error": "PE header not found"}
    coff = pe_offset + 4
    machine = int.from_bytes(data[coff : coff + 2], "little")
    sections_count = int.from_bytes(data[coff + 2 : coff + 4], "little")
    opt_size = int.from_bytes(data[coff + 16 : coff + 18], "little")
    opt = coff + 20
    magic = int.from_bytes(data[opt : opt + 2], "little") if opt + 2 <= len(data) else 0
    is_64 = magic == 0x20B
    dll_chars_offset = opt + (0x46 if not is_64 else 0x5E)
    dll_chars = int.from_bytes(data[dll_chars_offset : dll_chars_offset + 2], "little") if dll_chars_offset + 2 <= len(data) else 0
    sections = _pe_sections(data, opt + opt_size, sections_count)
    strings_blob = b"\x00".join(s.encode("utf-8", errors="ignore") for s in extract_strings(data, max_strings=1000))
    suspicious_imports = [name for name in ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute"] if name.encode() in strings_blob]
    return {
        "format": "PE",
        "architecture": {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(machine, f"machine_{machine}"),
        "sections": sections,
        "imports_hint": suspicious_imports,
        "protections": {"nx": bool(dll_chars & 0x0100), "aslr": bool(dll_chars & 0x0040), "relro": None, "pie": bool(dll_chars & 0x0040)},
        "packer_hints": _packer_hints(sections),
    }


def _pe_sections(data: bytes, offset: int, count: int) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for index in range(min(count, 32)):
        base = offset + index * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        raw_size = int.from_bytes(data[base + 16 : base + 20], "little")
        raw_ptr = int.from_bytes(data[base + 20 : base + 24], "little")
        chunk = data[raw_ptr : raw_ptr + raw_size] if raw_ptr < len(data) else b""
        sections.append({"name": name, "size": raw_size, "entropy": shannon_entropy(chunk)})
    return sections


def _packer_hints(sections: list[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    names = {section.get("name", "").lower() for section in sections}
    if any(name.startswith("upx") for name in names):
        hints.append("UPX section names")
    if sections and sum(1 for section in sections if section.get("entropy", 0) > 7.2) >= max(1, len(sections) // 2):
        hints.append("many high-entropy sections")
    return hints
