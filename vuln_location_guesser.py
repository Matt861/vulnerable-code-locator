#!/usr/bin/env python3
"""
guess_vuln_locations.py

Parse vuln_code_locator.py JSON output and guess complete vulnerable code paths.

Input: JSON array of PatchAnalysis produced by vuln_code_locator.py (--out results.json)
Output: ranked candidate "vulnerable locations" with best-effort full symbol paths.

Examples:
  python guess_vuln_locations.py results.json --format text
  python guess_vuln_locations.py results.json --format json --out guessed.json
  python guess_vuln_locations.py results.json --min-confidence 0.45 --top 50

Notes:
- For Java/Kotlin, attempts to infer FQCN from common source roots (src/main/java, src/test/java, etc).
- Uses hunk.context when present; otherwise falls back to symbol_guess.
- If patch source_url includes /commit/<sha>.patch, will generate a git-show command pointing at pre-fix (<sha>^).
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple


COMMIT_PATCH_RE = re.compile(r"https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})\.patch")
PR_PATCH_RE = re.compile(r"https?://github\.com/([^/]+/[^/]+)/pull/\d+\.patch")

# Common language roots for FQCN/module inference
JAVA_ROOT_MARKERS = [
    "/src/main/java/",
    "/src/test/java/",
    "/src/integrationTest/java/",
    "/src/jmh/java/",
    "/src/java/",
    "/src/",
]
KOTLIN_ROOT_MARKERS = [
    "/src/main/kotlin/",
    "/src/test/kotlin/",
    "/src/kotlin/",
    "/src/",
]
PY_ROOT_MARKERS = [
    "/src/",
]


@dataclass
class CandidateLocation:
    # Patch/source info
    source_url: str
    repo: Optional[str]
    fix_sha: Optional[str]

    # File/hunk info
    file_path: str
    old_start: int
    old_len: int
    old_end: int

    # Symbol guesses
    language: str
    fq_container: Optional[str]      # e.g., com.foo.Bar
    symbol: Optional[str]            # e.g., readObject
    context: Optional[str]           # raw diff context
    best_path: str                   # e.g., com.foo.Bar#readObject or file::symbol

    # Evidence + scoring
    removed_line_count: int
    added_line_count: int
    confidence: float

    # Optional helper command
    git_show_cmd: Optional[str]


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _ext_language(file_path: str) -> str:
    p = PurePosixPath(file_path)
    ext = p.suffix.lower()
    return {
        ".java": "java",
        ".kt": "kotlin",
        ".scala": "scala",
        ".groovy": "groovy",
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".cs": "csharp",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".cc": "cpp",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
    }.get(ext, "unknown")


def _extract_repo_and_sha(source_url: str, repo_field: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    m = COMMIT_PATCH_RE.match(source_url)
    if m:
        return m.group(1), m.group(2)
    m2 = PR_PATCH_RE.match(source_url)
    if m2:
        return m2.group(1), None
    return repo_field, None


def _strip_prefix(s: str, prefix: str) -> str:
    return s[len(prefix):] if s.startswith(prefix) else s


def _infer_fqcn_from_path(file_path: str, markers: List[str], suffixes: Iterable[str]) -> Optional[str]:
    """
    Infer Java/Kotlin-style container name from file path:
      .../src/main/java/com/foo/Bar.java  -> com.foo.Bar
    """
    norm = "/" + str(PurePosixPath(file_path)).lstrip("/")
    for marker in markers:
        if marker in norm:
            after = norm.split(marker, 1)[1]
            for suf in suffixes:
                if after.endswith(suf):
                    after = after[: -len(suf)]
            after = after.strip("/")
            if not after:
                return None
            return after.replace("/", ".")
    return None


def _infer_python_module(file_path: str) -> Optional[str]:
    norm = "/" + str(PurePosixPath(file_path)).lstrip("/")
    # try typical src/ layout first
    for marker in PY_ROOT_MARKERS:
        if marker in norm:
            after = norm.split(marker, 1)[1]
            if after.endswith(".py"):
                after = after[:-3]
            after = after.strip("/")
            if not after:
                return None
            # treat __init__.py as package
            if after.endswith("/__init__"):
                after = after[: -len("/__init__")]
            return after.replace("/", ".")
    # fallback: whole path without extension
    if norm.endswith(".py"):
        after = norm.strip("/")[0:-3]
        if after.endswith("/__init__"):
            after = after[: -len("/__init__")]
        return after.replace("/", ".")
    return None


_METHOD_FROM_CONTEXT_RE = re.compile(r"\b([A-Za-z_][\w$]*)\s*\(")


def _best_symbol(context: Optional[str], symbol_guess: Optional[str]) -> Optional[str]:
    if context:
        # try to extract function/method-looking token from context
        m = _METHOD_FROM_CONTEXT_RE.search(context)
        if m:
            return m.group(1)
    return symbol_guess or None


def _best_container_and_path(language: str, file_path: str, symbol: Optional[str]) -> Tuple[Optional[str], str]:
    """
    Return (fq_container, best_path_string).
    """
    lang = language.lower()
    if lang == "java":
        fqcn = _infer_fqcn_from_path(file_path, JAVA_ROOT_MARKERS, [".java"])
        if fqcn and symbol:
            return fqcn, f"{fqcn}#{symbol}"
        if fqcn:
            return fqcn, fqcn
        return None, f"{file_path}::{symbol}" if symbol else file_path

    if lang in {"kotlin", "scala", "groovy"}:
        markers = KOTLIN_ROOT_MARKERS if lang == "kotlin" else JAVA_ROOT_MARKERS
        suffix = ".kt" if lang == "kotlin" else (".scala" if lang == "scala" else ".groovy")
        fqcn = _infer_fqcn_from_path(file_path, markers, [suffix])
        if fqcn and symbol:
            return fqcn, f"{fqcn}#{symbol}"
        if fqcn:
            return fqcn, fqcn
        return None, f"{file_path}::{symbol}" if symbol else file_path

    if lang == "python":
        mod = _infer_python_module(file_path)
        if mod and symbol:
            return mod, f"{mod}:{symbol}"
        if mod:
            return mod, mod
        return None, f"{file_path}::{symbol}" if symbol else file_path

    # generic fallback
    return None, f"{file_path}::{symbol}" if symbol else file_path


def _confidence(context: Optional[str],
                symbol_guess: Optional[str],
                removed_count: int,
                added_count: int) -> float:
    """
    Heuristic confidence in (file + symbol) as a useful "vulnerable location pointer".
    """
    score = 0.0
    if removed_count > 0:
        score += 0.45
    if added_count > 0:
        score += 0.15
    if context:
        score += 0.25
    if symbol_guess:
        score += 0.15
    return min(1.0, score)


def _git_show_cmd(repo: Optional[str], fix_sha: Optional[str], file_path: str, old_start: int, old_len: int,
                  context_lines: int = 20) -> Optional[str]:
    """
    Produce a ready-to-run command after cloning:
      git show <fix_sha>^:<path> | nl -ba | sed -n 'start,endp'
    """
    if not fix_sha:
        return None
    start = max(1, old_start - context_lines)
    end = max(start, old_start + max(old_len, 1) + context_lines)
    # This assumes the user is inside the repo clone already.
    return (
        f"git show {fix_sha}^:{file_path} | nl -ba | sed -n '{start},{end}p'"
    )


def iter_candidates(data: List[Dict[str, Any]]) -> List[CandidateLocation]:
    out: List[CandidateLocation] = []
    for analysis in data:
        source_url = analysis.get("source_url") or ""
        repo_field = analysis.get("repo")
        repo, fix_sha = _extract_repo_and_sha(source_url, repo_field)

        for fd in analysis.get("file_diffs") or []:
            file_path = fd.get("path") or ""
            lang = _ext_language(file_path)

            for h in fd.get("hunks") or []:
                old_start = _safe_int(h.get("old_start"), 0)
                old_len = _safe_int(h.get("old_len"), 0)
                old_end = max(old_start, old_start + max(old_len, 1) - 1)

                context = h.get("context") or None
                symbol_guess = h.get("symbol_guess") or None
                removed = h.get("removed") or []
                added = h.get("added") or []

                removed_count = sum(1 for x in removed if isinstance(x, str) and not x.startswith("..."))
                added_count = sum(1 for x in added if isinstance(x, str) and not x.startswith("..."))

                symbol = _best_symbol(context, symbol_guess)
                fq_container, best_path = _best_container_and_path(lang, file_path, symbol)

                conf = _confidence(context, symbol_guess, removed_count, added_count)
                cmd = _git_show_cmd(repo, fix_sha, file_path, old_start, old_len)

                out.append(CandidateLocation(
                    source_url=source_url,
                    repo=repo,
                    fix_sha=fix_sha,
                    file_path=file_path,
                    old_start=old_start,
                    old_len=old_len,
                    old_end=old_end,
                    language=lang,
                    fq_container=fq_container,
                    symbol=symbol,
                    context=context,
                    best_path=best_path,
                    removed_line_count=removed_count,
                    added_line_count=added_count,
                    confidence=conf,
                    git_show_cmd=cmd,
                ))
    return out


def group_candidates(cands: List[CandidateLocation]) -> List[CandidateLocation]:
    """
    Optional: merge adjacent/duplicate hunks that point to the same best_path within the same patch.
    """
    key_map: Dict[Tuple[str, str, str], CandidateLocation] = {}
    for c in cands:
        key = (c.source_url, c.file_path, c.best_path)
        if key not in key_map:
            key_map[key] = c
        else:
            existing = key_map[key]
            # expand line range
            existing.old_start = min(existing.old_start, c.old_start)
            existing.old_end = max(existing.old_end, c.old_end)
            existing.old_len = (existing.old_end - existing.old_start + 1)
            # aggregate evidence
            existing.removed_line_count += c.removed_line_count
            existing.added_line_count += c.added_line_count
            existing.confidence = min(1.0, max(existing.confidence, c.confidence) + 0.05)
            # keep cmd consistent
            if existing.git_show_cmd is None and c.git_show_cmd:
                existing.git_show_cmd = c.git_show_cmd
    return list(key_map.values())


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse vuln_code_locator.py JSON output and guess vulnerable code paths.")
    ap.add_argument("input_json", help="Path to vuln_code_locator.py results JSON file.")
    ap.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    ap.add_argument("--out", default=None, help="Write output to file (default: stdout).")
    ap.add_argument("--top", type=int, default=100, help="Max candidates to output after ranking.")
    ap.add_argument("--min-confidence", type=float, default=0.0, help="Filter out candidates below this confidence (0..1).")
    ap.add_argument("--group", action="store_true", help="Merge duplicates by (patch,file,best_path).")
    args = ap.parse_args()

    with open(args.input_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    cands = iter_candidates(data)
    if args.group:
        cands = group_candidates(cands)

    # Rank: confidence first, then more removed lines, then more added lines
    cands.sort(key=lambda c: (c.confidence, c.removed_line_count, c.added_line_count), reverse=True)

    # Filter
    cands = [c for c in cands if c.confidence >= args.min_confidence]
    cands = cands[: max(0, args.top)]

    if args.format == "json":
        payload = [asdict(c) for c in cands]
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        lines: List[str] = []
        for i, c in enumerate(cands, start=1):
            lines.append("=" * 90)
            lines.append(f"[{i}] {c.best_path}")
            lines.append(f"  confidence: {c.confidence:.2f}  removed:{c.removed_line_count}  added:{c.added_line_count}")
            lines.append(f"  language: {c.language}")
            lines.append(f"  file: {c.file_path}")
            lines.append(f"  pre-fix lines: {c.old_start}-{c.old_end} (len={c.old_len})")
            if c.context:
                lines.append(f"  context: {c.context}")
            if c.repo:
                lines.append(f"  repo: {c.repo}")
            if c.fix_sha:
                lines.append(f"  fix_sha: {c.fix_sha}")
            lines.append(f"  patch: {c.source_url}")
            if c.git_show_cmd:
                lines.append("  view (inside repo clone):")
                lines.append(f"    {c.git_show_cmd}")
        text = "\n".join(lines) + ("\n" if lines else "")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())