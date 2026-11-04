"""Turn raw logs into something safe to post in chat and to show an agent.

Logs are untrusted: they can carry secrets (leaked by the app or the build) and text an
attacker chose ("ignore your rules and deploy"). So we strip secrets, defuse mentions and
fences, trim, and label the result as data.
"""
from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

_REDACTIONS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[private key removed]"),
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic|token)?\s*[A-Za-z0-9._~+/=|-]{6,}"), r"\1: [redacted]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=|-]{10,}"), "bearer [redacted]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"), "[github token]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "[api key]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[aws key id]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[slack token]"),
    (re.compile(r"\b[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b"), "[discord token]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[jwt]"),
    (re.compile(r"\b\d{1,6}\|[A-Za-z0-9]{30,}\b"), "[coolify token]"),
    (re.compile(r"(?i)\b([A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)[A-Z0-9_.-]*)\s*[=:]\s*(?:\"[^\"]*\"|'[^']*'|\S+)"), r"\1=[redacted]"),
    (re.compile(r"(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@"), r"\1://[user]:[redacted]@"),
]

MAX_LINE = 300


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def defuse(text: str) -> str:
    """Stop log text from mentioning people or agents, or breaking out of a code fence."""
    text = text.replace("```", "'''")
    text = text.replace("<@", "<​@")           # Discord mentions
    return re.sub(r"@(?=[A-Za-z0-9_.-])", "@​", text)   # Mattermost / Slack style


def clean_lines(lines: list[str], limit: int = 40) -> list[str]:
    """Strip ANSI and blank lines, redact, defuse, keep the last `limit` lines."""
    out = []
    for raw in lines:
        for line in str(raw).splitlines():
            line = _ANSI.sub("", line).rstrip()
            if line.strip():
                out.append(defuse(redact(line))[:MAX_LINE])
    return out[-limit:]


def fenced(lines: list[str]) -> str:
    body = "\n".join(lines) if lines else "(no log output was available)"
    return f"```\n{body}\n```"
