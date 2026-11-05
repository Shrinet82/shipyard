"""Reviewer suggestions: find the ```suggestion blocks people wrote on a pull request, and apply them to the branch.

Nothing here writes code of its own. A suggestion is text a human reviewer typed in a GitHub review comment; applying it is what the
"Apply suggestion" button does. The Gatekeeper does it only after a maintainer asks and a second person approves, pinned to the head
commit that was approved, and only for suggestions that are still current, written by someone with write access, on a same-repository
branch, and not touching the CI workflows.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any

BLOCK = re.compile(r"```suggestion[^\S\r\n]*\r?\n(.*?)(?:\r?\n)?```", re.S)
TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
MAX_SUGGESTIONS = 25
MAX_LINES = 200
MAX_FILE_BYTES = 1_000_000
REFUSED_PATHS = (".github/workflows/", ".github/actions/", ".git/")


class SuggestionError(ValueError):
    """Why a suggestion cannot be applied; safe to show."""


@dataclass(frozen=True)
class Suggestion:
    id: int
    path: str
    start: int          # first line replaced, 1-based
    end: int            # last line replaced
    text: str           # the replacement ("" deletes the lines)
    author: str
    url: str
    author_id: int = 0

    def digest(self) -> str:
        return hashlib.sha256(f"{self.id}|{self.path}|{self.start}|{self.end}|{self.text}".encode()).hexdigest()[:16]

    @property
    def lines(self) -> list[str]:
        return self.text.split("\n") if self.text else []


def _refused_path(path: str) -> str | None:
    if any(path.startswith(p) for p in REFUSED_PATHS) or "/.git/" in path:
        return "it touches the CI workflows or git internals"
    if path.startswith("/") or ".." in path.split("/"):
        return "the path is not a repository path"
    return None


def parse(comments: list[dict[str, Any]], head_sha: str) -> tuple[list[Suggestion], list[str]]:
    """(usable suggestions, why each other suggestion was left out). Only current comments on the head commit by trusted people."""
    out: list[Suggestion] = []
    skipped: list[str] = []
    for c in comments:
        m = BLOCK.search(c.get("body") or "")
        if not m:
            continue
        who = (c.get("user") or {}).get("login", "?")
        label = f"#{c.get('id')} by {who} on {c.get('path')}"
        text = m.group(1)
        end = c.get("line") or c.get("original_line")
        start = c.get("start_line") or end
        if c.get("side", "RIGHT") != "RIGHT" or end is None:
            skipped.append(f"{label}: it is on removed lines")
        elif c.get("position") is None or c.get("commit_id") != head_sha:
            skipped.append(f"{label}: it is out of date (the branch has moved)")
        elif c.get("author_association") not in TRUSTED:
            skipped.append(f"{label}: {who} does not have write access to the repository")
        elif (why := _refused_path(str(c.get("path", "")))):
            skipped.append(f"{label}: {why}")
        elif start > end or text.count("\n") + 1 > MAX_LINES or len(text) > 20_000:
            skipped.append(f"{label}: it is too large")
        else:
            out.append(Suggestion(int(c["id"]), str(c["path"]), int(start), int(end), text, who, str(c.get("html_url", "")), int((c.get("user") or {}).get("id") or 0)))
    out.sort(key=lambda s: s.id)
    return out[:MAX_SUGGESTIONS], skipped


def decode(content: dict[str, Any]) -> str:
    if content.get("encoding") != "base64" or content.get("size", 0) > MAX_FILE_BYTES:
        raise SuggestionError("the file is too large or not a plain text file")
    try:
        return base64.b64decode(content["content"]).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise SuggestionError("the file is not UTF-8 text") from None


def apply_to_text(text: str, chosen: list[Suggestion]) -> str:
    """The file with each chosen suggestion's lines replaced. Overlapping suggestions are refused, not merged."""
    ordered = sorted(chosen, key=lambda s: s.start, reverse=True)           # bottom first, so earlier line numbers stay valid
    for a, b in zip(ordered, ordered[1:]):
        if b.end >= a.start:
            raise SuggestionError(f"suggestions #{a.id} and #{b.id} overlap; apply one at a time")
    newline = "\r\n" if "\r\n" in text else "\n"
    trailing = text.endswith(("\n", "\r\n"))
    lines = text.split("\r\n" if newline == "\r\n" else "\n")
    if trailing:
        lines = lines[:-1]
    for s in ordered:
        if s.end > len(lines):
            raise SuggestionError(f"#{s.id} points past the end of {s.path}")
        lines[s.start - 1:s.end] = s.lines
    return newline.join(lines) + (newline if trailing else "")


def preview(s: Suggestion, old_lines: list[str]) -> list[str]:
    """A small diff for chat: the lines that go and the lines that come."""
    gone = [f"- {ln}" for ln in old_lines[s.start - 1:s.end]]
    new = [f"+ {ln}" for ln in s.lines]
    return [f"{s.path}:{s.start}" + (f"-{s.end}" if s.end != s.start else ""), *gone[:6], *new[:6]]
