#!/usr/bin/env python3
"""
Secrets Leak Detector
---------------------
A simple base tool that scans files and directories for hard-coded secrets
(API keys, tokens, private keys, passwords) using regex rules plus a
Shannon-entropy check for high-randomness strings.

Usage:
    python secrets_leak_detector.py <path> [<path> ...]
    python secrets_leak_detector.py . --format json --output report.json
    python secrets_leak_detector.py . --fail-on high      # for CI/CD gates

Exit codes:
    0 = no findings at or above the threshold
    1 = findings at or above the threshold
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Iterable, Iterator

# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: str


RULES: list[Rule] = [
    Rule("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    Rule(
        "AWS Secret Access Key",
        re.compile(r"(?i)aws.{0,20}(secret|key).{0,5}['\"=:\s]+([A-Za-z0-9/+=]{40})\b"),
        "high",
    ),
    Rule("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high"),
    Rule("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    Rule("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    Rule("Stripe Live Key", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{24,}\b"), "high"),
    Rule(
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "high",
    ),
    Rule(
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "medium",
    ),
    Rule(
        "Credentials in URL",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]{3,}@[^/\s]+"),
        "high",
    ),
    Rule(
        "Generic Secret Assignment",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
        "medium",
    ),
]

# Quoted strings that might be secrets purely because they look random.
HIGH_ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")
ENTROPY_THRESHOLD = 4.2  # bits per character

# Values that are obviously placeholders and should be ignored.
PLACEHOLDER_HINTS = (
    "example", "changeme", "your_", "your-", "<", "xxxx", "dummy",
    "placeholder", "sample", "test", "todo", "${", "{{", "os.environ", "getenv",
)

# Inline suppression marker, e.g.  token = "abc"  # nosecret
SUPPRESS_MARKER = "nosecret"

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".idea", ".vscode", ".tox", ".mypy_cache",
}
IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".jar", ".class", ".exe", ".dll", ".so", ".pyc", ".woff", ".woff2",
    ".ttf", ".mp3", ".mp4", ".lock",
}
MAX_FILE_SIZE = 1_000_000  # bytes


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    snippet: str  # redacted


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of a string in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact(secret: str, visible: int = 4) -> str:
    """Mask a secret so reports never leak the full value."""
    if len(secret) <= visible * 2:
        return "*" * len(secret)
    return f"{secret[:visible]}{'*' * (len(secret) - visible * 2)}{secret[-visible:]}"


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def iter_files(paths: Iterable[str]) -> Iterator[str]:
    for path in paths:
        if os.path.isfile(path):
            yield path
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for name in files:
                if os.path.splitext(name)[1].lower() in IGNORED_EXTENSIONS:
                    continue
                yield os.path.join(root, name)


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def scan_line(line: str) -> list[tuple[str, str, str]]:
    """Return a list of (rule_name, severity, matched_text) for one line."""
    if SUPPRESS_MARKER in line:
        return []

    hits: list[tuple[str, str, str]] = []
    matched_spans: list[tuple[int, int]] = []

    for rule in RULES:
        for match in rule.pattern.finditer(line):
            text = match.group(0)
            # For generic assignments, judge the value rather than the key name.
            value = match.group(match.lastindex) if match.lastindex else text
            if rule.name == "Generic Secret Assignment" and is_placeholder(value):
                continue
            hits.append((rule.name, rule.severity, text))
            matched_spans.append(match.span())

    for match in HIGH_ENTROPY_CANDIDATE.finditer(line):
        start, end = match.span()
        if any(start < e and end > s for s, e in matched_spans):
            continue  # already reported by a specific rule
        value = match.group(1)
        if is_placeholder(value):
            continue
        if shannon_entropy(value) >= ENTROPY_THRESHOLD:
            hits.append(("High-Entropy String", "low", value))

    return hits


def scan_file(path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return findings
        with open(path, "rb") as fh:
            if is_binary(fh.read(2048)):
                return findings
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, start=1):
                for rule_name, severity, text in scan_line(line):
                    findings.append(
                        Finding(path, lineno, rule_name, severity, redact(text))
                    )
    except (OSError, PermissionError) as exc:
        print(f"[warn] could not read {path}: {exc}", file=sys.stderr)
    return findings


def scan_paths(paths: Iterable[str]) -> list[Finding]:
    results: list[Finding] = []
    for file_path in iter_files(paths):
        results.extend(scan_file(file_path))
    return results


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def format_text(findings: list[Finding]) -> str:
    if not findings:
        return "No secrets detected."
    lines = []
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line)):
        lines.append(f"[{f.severity.upper():6}] {f.file}:{f.line}  {f.rule}  ->  {f.snippet}")
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    lines.append("")
    lines.append(
        f"Total: {len(findings)} finding(s)  "
        f"(high={counts['high']}, medium={counts['medium']}, low={counts['low']})"
    )
    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan files and directories for leaked secrets."
    )
    parser.add_argument("paths", nargs="+", help="Files or directories to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--output", help="Write the report to this file instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER),
        default="medium",
        help="Exit with code 1 if any finding is at or above this severity (default: medium)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    findings = scan_paths(args.paths)

    report = format_json(findings) if args.format == "json" else format_text(findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"Report written to {args.output}")
    else:
        print(report)

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
