#!/usr/bin/env python3
"""
vuln_code_locator.py

Locate likely vulnerable code locations for open-source software given a vulnerability ID
by *deriving* them from patch diffs (no CVEfixes, no prebuilt vulnerable-code database).

Default strategy:
  - Search GitHub PRs that mention the vulnerability ID (e.g., CVE-2024-12345).
  - Download each PR's .patch (unified diff).
  - Parse diffs for changed files and hunks, including hunk context and removed lines.

Requirements:
  - Python 3.9+
  - requests  (pip install requests)

Optional:
  - GITHUB_TOKEN env var (recommended; improves rate limits)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple, Set

import requests


GITHUB_API = "https://api.github.com"
GITHUB_COMMIT_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commit/[0-9a-fA-F]{7,40}")
GITHUB_PR_RE     = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/\d+")
GITHUB_COMMIT_SHA_FROM_URL_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commit/([0-9a-fA-F]{7,40})(?:\.patch)?/?$"
)


# ----------------------------
# Models
# ----------------------------

@dataclass
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    context: str  # trailing text after @@ ... @@ (often function name)
    symbol_guess: Optional[str]  # heuristic function/method name
    removed: List[str]  # lines removed (candidate vulnerable code)
    added: List[str]  # lines added (fixed code)
    near_context: List[str]  # a few unchanged/context lines around change


@dataclass
class FileDiff:
    path: str
    hunks: List[Hunk]


@dataclass
class PatchAnalysis:
    source_url: str  # PR/commit patch URL
    commit_sha: Optional[str]  # explicit when source_url is a commit patch
    repo: Optional[str]
    title: Optional[str]
    file_diffs: List[FileDiff]


def extract_github_refs_from_snyk_html(html: str) -> List[str]:
    """
    Pull GitHub commit / PR links from a Snyk vulnerability page HTML.
    Returns unique URLs, commits first.
    """
    commits = GITHUB_COMMIT_RE.findall(html)
    prs = GITHUB_PR_RE.findall(html)

    # de-dupe while preserving order
    seen: Set[str] = set()
    out: List[str] = []
    for u in commits + prs:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def to_github_patch_url(url: str) -> str:
    """
    Convert a GitHub commit/PR URL to a patch URL.
    - commit: https://github.com/o/r/commit/<sha> -> .../<sha>.patch
    - PR:     https://github.com/o/r/pull/<n>     -> .../<n>.patch
    """
    return url.rstrip("/") + ".patch"


def analyze_from_snyk_url(
    snyk_url: str,
    token: Optional[str],
    pause_s: float,
    language: Optional[str],
    max_hunks_per_file: int,
    max_lines_per_list: int,
) -> List[PatchAnalysis]:
    """
    1) Download Snyk vuln page
    2) Extract referenced GitHub commits/PRs
    3) Download each .patch and parse diffs
    """
    snyk_html = download_text(snyk_url, token=None, pause_s=pause_s)  # Snyk doesn't use GitHub token
    refs = extract_github_refs_from_snyk_html(snyk_html)

    analyses: List[PatchAnalysis] = []
    for ref in refs:
        patch_url = to_github_patch_url(ref)
        commit_sha = extract_commit_sha(patch_url) or extract_commit_sha(ref)
        try:
            patch_text = download_text(patch_url, token=token, pause_s=pause_s)  # GitHub token helps here
            file_diffs = parse_github_patch(patch_text, language=language, max_hunks_per_file=max_hunks_per_file)

            for fd in file_diffs:
                for h in fd.hunks:
                    h.removed = clip_lines(h.removed, max_lines_per_list)
                    h.added = clip_lines(h.added, max_lines_per_list)
                    h.near_context = clip_lines(h.near_context, max_lines_per_list)

            analyses.append(PatchAnalysis(
                source_url=patch_url,
                commit_sha=commit_sha,
                repo=_repo_from_pr_url(ref),
                title=f"Referenced by {snyk_url}",
                file_diffs=file_diffs,
            ))
        except Exception as e:
            print(f"[WARN] Failed to analyze {patch_url}: {e}", file=sys.stderr)
            analyses.append(PatchAnalysis(
                source_url=patch_url,
                repo=_repo_from_pr_url(ref),
                title=f"Referenced by {snyk_url}",
                file_diffs=[],
            ))
    return analyses


# ----------------------------
# GitHub helpers
# ----------------------------

def extract_commit_sha(url: str) -> Optional[str]:
    """
    If url is a GitHub commit URL or commit patch URL, return the commit SHA.
    Otherwise return None (e.g., PR patch URLs).
    """
    if not url:
        return None
    m = GITHUB_COMMIT_SHA_FROM_URL_RE.match(url.strip())
    return m.group(1) if m else None


def github_headers(token: Optional[str]) -> Dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "vuln-code-locator/1.0",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def github_search_prs(
    vuln_id: str,
    token: Optional[str],
    repo: Optional[str],
    max_results: int,
    pause_s: float,
) -> List[Dict]:
    """
    Search GitHub PRs mentioning vuln_id.

    Uses:
      GET /search/issues?q=...  (PRs are issues with is:pr)
    """
    q_parts = [f'"{vuln_id}"', "is:pr", "in:title,body"]
    if repo:
        # repo format: owner/name
        q_parts.append(f"repo:{repo}")

    q = " ".join(q_parts)
    per_page = min(100, max_results)
    url = f"{GITHUB_API}/search/issues"
    params = {"q": q, "per_page": per_page, "page": 1}

    items: List[Dict] = []
    while len(items) < max_results:
        resp = requests.get(url, headers=github_headers(token), params=params, timeout=30)
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            raise RuntimeError(
                "GitHub rate limit hit. Set GITHUB_TOKEN env var (recommended) and retry."
            )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("items") or []
        if not batch:
            break

        items.extend(batch)
        if len(batch) < per_page:
            break

        params["page"] += 1
        time.sleep(pause_s)

    return items[:max_results]


def to_patch_url(html_url: str) -> str:
    # GitHub supports appending .patch to PR URLs.
    return html_url.rstrip("/") + ".patch"


def download_text(url: str, token: Optional[str], pause_s: float) -> str:
    resp = requests.get(url, headers=github_headers(token), timeout=60, allow_redirects=True)
    resp.raise_for_status()
    time.sleep(pause_s)
    return resp.text


# ----------------------------
# Patch parsing
# ----------------------------

_DIFF_START_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)\s*$")
_HUNK_RE = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$"
)

def guess_symbol(lines: Iterable[str], language: Optional[str]) -> Optional[str]:
    """
    Best-effort guess of a function/method name based on nearby lines.
    This is heuristic and will be wrong sometimes.
    """
    text = "\n".join(lines)

    # If user forced language, prioritize that, else try several patterns.
    patterns: List[Tuple[str, re.Pattern]] = []

    if language:
        lang = language.lower()
        if lang in {"java", "kotlin", "scala", "groovy", "csharp", "cs", "c#"}:
            patterns.append(("jvm", re.compile(r"\b([A-Za-z_]\w*)\s*\(", re.MULTILINE)))
        elif lang in {"python", "py"}:
            patterns.append(("py", re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)))
        elif lang in {"javascript", "js", "typescript", "ts"}:
            patterns.append(("js", re.compile(r"^\s*(?:function\s+([A-Za-z_]\w*)\s*\(|([A-Za-z_]\w*)\s*=\s*\(|([A-Za-z_]\w*)\s*\([^)]*\)\s*{)", re.MULTILINE)))
        else:
            patterns.append(("generic", re.compile(r"\b([A-Za-z_]\w*)\s*\(", re.MULTILINE)))
    else:
        patterns.extend([
            ("py", re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)),
            ("java-ish", re.compile(r"^\s*(?:public|protected|private|static|\s)*.*?\b([A-Za-z_]\w*)\s*\(", re.MULTILINE)),
            ("js-ish", re.compile(r"^\s*(?:function\s+([A-Za-z_]\w*)\s*\(|([A-Za-z_]\w*)\s*:\s*function\s*\(|([A-Za-z_]\w*)\s*=\s*function\s*\(|([A-Za-z_]\w*)\s*\([^)]*\)\s*{)", re.MULTILINE)),
            ("generic", re.compile(r"\b([A-Za-z_]\w*)\s*\(", re.MULTILINE)),
        ])

    for _, pat in patterns:
        m = pat.search(text)
        if not m:
            continue
        # pick the first non-empty capture group
        for g in m.groups():
            if g:
                return g
        # or group(1) for single-group patterns
        if m.lastindex and m.group(1):
            return m.group(1)

    return None


def parse_github_patch(patch_text: str, language: Optional[str], max_hunks_per_file: int) -> List[FileDiff]:
    """
    Parse a unified diff (like GitHub .patch) into file diffs and hunks.
    """
    file_diffs: List[FileDiff] = []
    current_file: Optional[FileDiff] = None
    current_hunk: Optional[Hunk] = None

    # We'll store a small rolling window of non +/- lines to use as context.
    rolling_context: List[str] = []

    def flush_hunk():
        nonlocal current_hunk, current_file
        if current_hunk and current_file:
            current_file.hunks.append(current_hunk)
        current_hunk = None

    def flush_file():
        nonlocal current_file
        if current_file:
            # enforce per-file hunk limit
            if max_hunks_per_file > 0:
                current_file.hunks = current_file.hunks[:max_hunks_per_file]
            file_diffs.append(current_file)
        current_file = None

    lines = patch_text.splitlines()
    for line in lines:
        m = _DIFF_START_RE.match(line)
        if m:
            flush_hunk()
            flush_file()
            # prefer b/ path
            b_path = m.group(2)
            current_file = FileDiff(path=b_path, hunks=[])
            rolling_context.clear()
            continue

        mh = _HUNK_RE.match(line)
        if mh and current_file:
            flush_hunk()
            old_start = int(mh.group(1))
            old_len = int(mh.group(2) or "1")
            new_start = int(mh.group(3))
            new_len = int(mh.group(4) or "1")
            context = (mh.group(5) or "").strip()
            current_hunk = Hunk(
                old_start=old_start,
                old_len=old_len,
                new_start=new_start,
                new_len=new_len,
                context=context,
                symbol_guess=None,
                removed=[],
                added=[],
                near_context=[],
            )
            # seed near_context with rolling context
            current_hunk.near_context.extend(rolling_context[-8:])
            continue

        if not current_file:
            continue

        # Skip patch headers, file markers
        if line.startswith("--- ") or line.startswith("+++ ") or line.startswith("index "):
            continue

        if current_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk.added.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk.removed.append(line[1:])
            else:
                # unchanged line or patch metadata
                # keep a little context within the hunk
                if line.startswith(" "):
                    current_hunk.near_context.append(line[1:])
                elif line and not line.startswith("\\"):
                    current_hunk.near_context.append(line)

            # Update rolling context when line is not a change marker
            if not (line.startswith("+") or line.startswith("-")) and line.strip():
                rolling_context.append(line.lstrip(" "))

            # Keep rolling context small
            if len(rolling_context) > 20:
                rolling_context = rolling_context[-20:]

        else:
            # outside a hunk: maintain context lightly
            if line.strip():
                rolling_context.append(line.lstrip(" "))
                if len(rolling_context) > 20:
                    rolling_context = rolling_context[-20:]

    flush_hunk()
    flush_file()

    # Fill symbol_guess for each hunk using context + nearby lines + removed lines
    for fd in file_diffs:
        for h in fd.hunks:
            source_lines = []
            if h.context:
                source_lines.append(h.context)
            source_lines.extend(h.near_context[-10:])
            source_lines.extend(h.removed[:10])
            source_lines.extend(h.added[:10])
            h.symbol_guess = guess_symbol(source_lines, language)

    return file_diffs


def clip_lines(lines: List[str], max_lines: int) -> List[str]:
    if max_lines <= 0 or len(lines) <= max_lines:
        return lines
    return lines[:max_lines] + [f"... ({len(lines) - max_lines} more lines)"]


# ----------------------------
# Main workflow
# ----------------------------

def analyze_from_github_prs(
    vuln_id: str,
    token: Optional[str],
    repo: Optional[str],
    max_results: int,
    pause_s: float,
    language: Optional[str],
    max_hunks_per_file: int,
    max_lines_per_list: int,
) -> List[PatchAnalysis]:
    prs = github_search_prs(
        vuln_id=vuln_id,
        token=token,
        repo=repo,
        max_results=max_results,
        pause_s=pause_s,
    )

    analyses: List[PatchAnalysis] = []
    for pr in prs:
        html_url = pr.get("html_url") or ""
        title = pr.get("title")
        patch_url = to_patch_url(html_url)
        commit_sha = extract_commit_sha(patch_url)
        try:
            patch_text = download_text(patch_url, token=token, pause_s=pause_s)
            file_diffs = parse_github_patch(patch_text, language=language, max_hunks_per_file=max_hunks_per_file)

            # clip output sizes
            for fd in file_diffs:
                for h in fd.hunks:
                    h.removed = clip_lines(h.removed, max_lines_per_list)
                    h.added = clip_lines(h.added, max_lines_per_list)
                    h.near_context = clip_lines(h.near_context, max_lines_per_list)

            analyses.append(
                PatchAnalysis(
                    source_url=patch_url,
                    commit_sha=commit_sha,
                    repo=repo or _repo_from_pr_url(html_url),
                    title=title,
                    file_diffs=file_diffs,
                )
            )
        except Exception as e:
            # Keep going; some patches will fail to fetch
            analyses.append(
                PatchAnalysis(
                    source_url=patch_url,
                    commit_sha=commit_sha,
                    repo=repo or _repo_from_pr_url(html_url),
                    title=title,
                    file_diffs=file_diffs,
                )
            )
            print(f"[WARN] Failed to analyze {patch_url}: {e}", file=sys.stderr)

    return analyses


def _repo_from_pr_url(url: str) -> Optional[str]:
    # https://github.com/OWNER/REPO/pull/123
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/", url)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


def as_jsonable(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    raise TypeError(obj)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Locate likely vulnerable code locations by deriving them from patch diffs (no CVEfixes)."
    )
    ap.add_argument("vuln_id", help="Vulnerability ID (e.g., CVE-2024-12345).")
    ap.add_argument("--github-repo", default=None, help="Optional: restrict search to a repo (OWNER/REPO).")
    ap.add_argument("--max-results", type=int, default=10, help="Max PRs to analyze (default: 10).")
    ap.add_argument("--pause", type=float, default=0.35, help="Pause between requests in seconds (default: 0.35).")
    ap.add_argument("--language", default=None, help="Optional language hint (java/python/js/etc.) for symbol guessing.")
    ap.add_argument("--max-hunks-per-file", type=int, default=50, help="Limit hunks per file (default: 50; 0 = unlimited).")
    ap.add_argument("--max-lines", type=int, default=80, help="Clip removed/added/context lists to N lines (default: 80; 0 = unlimited).")
    ap.add_argument("--out", default=None, help="Write JSON results to this file.")
    ap.add_argument("--print", action="store_true", help="Print a short human-readable summary.")
    ap.add_argument("--snyk-url", default=None,
                    help="Snyk vulnerability URL to extract referenced fix commits/PRs from.")
    args = ap.parse_args()

    token = ""  # optional but recommended

    if args.snyk_url:
        analyses = analyze_from_snyk_url(
            snyk_url=args.snyk_url,
            token=token,  # GitHub token for fetching patches
            pause_s=max(0.0, args.pause),
            language=args.language,
            max_hunks_per_file=args.max_hunks_per_file,
            max_lines_per_list=args.max_lines,
        )
    else:
        try:
            analyses = analyze_from_github_prs(
                vuln_id=args.vuln_id.strip(),
                token=token,
                repo=args.github_repo,
                max_results=max(1, args.max_results),
                pause_s=max(0.0, args.pause),
                language=args.language,
                max_hunks_per_file=args.max_hunks_per_file,
                max_lines_per_list=args.max_lines,
            )
        except Exception as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 2

    payload = [as_jsonable(a) for a in analyses]

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"Wrote {args.out}")

    if args.print:
        for a in analyses:
            print("=" * 90)
            print(f"Patch: {a.source_url}")
            if a.commit_sha:
                print(f"Commit SHA: {a.commit_sha}")
            if a.title:
                print(f"Title: {a.title}")
            if not a.file_diffs:
                print("No diffs parsed (fetch failed or patch empty).")
                continue
            print(f"Files changed: {len(a.file_diffs)}")
            for fd in a.file_diffs[:20]:
                print(f"  - {fd.path} (hunks={len(fd.hunks)})")
                for h in fd.hunks[:3]:
                    sym = h.symbol_guess or (h.context if h.context else "<?>")
                    print(f"      @@ -{h.old_start},{h.old_len} +{h.new_start},{h.new_len} @@  symbol={sym}")
                    if h.removed:
                        print(f"        removed_lines={len([x for x in h.removed if not x.startswith('...')])}")
                    if h.added:
                        print(f"        added_lines={len([x for x in h.added if not x.startswith('...')])}")

    # If no output file and not printing, emit JSON to stdout (useful for piping)
    if not args.out and not args.print:
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())