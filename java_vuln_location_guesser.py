#!/usr/bin/env python3
"""
guess_java_vuln_locations.py

Parse vuln_code_locator.py JSON output and guess "complete" vulnerable code paths for Java:
  package.Class[.Inner]#method(paramTypes)

Works best when vuln_code_locator.py analyzed commit patches (…/commit/<sha>.patch).
For PR patches, a fix SHA may be unavailable, so git-show commands may be omitted.

Usage:
  python guess_java_vuln_locations.py results.json --min-confidence 0.55 --top 50 --group --format text
  python guess_java_vuln_locations.py results.json --format json --out guessed.json

Input format: JSON array output from vuln_code_locator.py (--out results.json)
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple


# --- GitHub patch URL parsing (for optional git-show commands) ---
COMMIT_PATCH_RE = re.compile(r"https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})\.patch")
PR_PATCH_RE = re.compile(r"https?://github\.com/([^/]+/[^/]+)/pull/\d+\.patch")

# --- Java path → package/class inference ---
JAVA_ROOT_MARKERS = [
    "/src/main/java/",
    "/src/test/java/",
    "/src/integrationTest/java/",
    "/src/jmh/java/",
    "/src/java/",
    "/src/",
]

# --- Java parsing regexes ---
PACKAGE_RE = re.compile(r"^\s*package\s+([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*;\s*$")
# type decl: class/interface/enum/record (ignore annotations and modifiers)
TYPE_RE = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public|protected|private|abstract|final|static|sealed|non-sealed|\s)+\s*"
    r"(class|interface|enum|record)\s+([A-Za-z_]\w*)\b"
)
# method/ctor decl (best-effort). Handles generics, annotations, throws, etc.
METHOD_RE = re.compile(
    r"""^\s*
        (?:@\w+(?:\([^)]*\))?\s*)*                                  # annotations
        (?:(?:public|protected|private|static|final|abstract|synchronized|native|strictfp)\s+)*  # modifiers
        (?:<[^>]+>\s+)?                                              # method generics
        (?:
            (?P<rtype>[\w\.\[\]<>?,\s]+?)\s+                        # return type (lazy)
        )?
        (?P<name>[A-Za-z_]\w*)\s*                                   # method/ctor name
        \(\s*(?P<params>[^)]*)\)\s*                                  # params
        (?:throws\s+[\w\.\s,]+)?\s*                                  # throws
        (?:\{|;)?\s*$                                                # open brace or semicolon
    """,
    re.VERBOSE,
)

# remove comments quickly (diff context lines usually don't include block comments, but safe)
LINE_COMMENT_RE = re.compile(r"//.*$")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/")


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _normalize_ws(s: str) -> str:
    return " ".join(s.strip().split())


def _strip_inline_comments(s: str) -> str:
    s = BLOCK_COMMENT_RE.sub("", s)
    s = LINE_COMMENT_RE.sub("", s)
    return s.rstrip()


def _extract_repo_and_sha(source_url: str, repo_field: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    m = COMMIT_PATCH_RE.match(source_url or "")
    if m:
        return m.group(1), m.group(2)
    m2 = PR_PATCH_RE.match(source_url or "")
    if m2:
        return m2.group(1), None
    return repo_field, None


def _infer_fqcn_from_path(file_path: str) -> Optional[str]:
    """
    Best-effort: src/main/java/com/foo/Bar.java -> com.foo.Bar
    """
    norm = "/" + str(PurePosixPath(file_path)).lstrip("/")
    if not norm.endswith(".java"):
        return None
    for marker in JAVA_ROOT_MARKERS:
        if marker in norm:
            after = norm.split(marker, 1)[1]
            if after.endswith(".java"):
                after = after[:-5]
            after = after.strip("/")
            if not after:
                return None
            return after.replace("/", ".")
    # fallback: drop extension and replace slashes
    after = norm.strip("/")
    after = after[:-5] if after.endswith(".java") else after
    return after.replace("/", ".")


def _file_basename_class(file_path: str) -> Optional[str]:
    p = PurePosixPath(file_path)
    if p.suffix.lower() != ".java":
        return None
    return p.stem or None


def _pick_last_match(regex: re.Pattern, lines: List[str]) -> Optional[re.Match]:
    last = None
    for ln in lines:
        m = regex.match(ln)
        if m:
            last = m
    return last


def _extract_package(lines: List[str]) -> Optional[str]:
    # pick last package decl encountered (rarely more than one)
    m = _pick_last_match(PACKAGE_RE, lines)
    return m.group(1) if m else None


def _extract_nearest_type(lines: List[str]) -> Optional[str]:
    """
    Find the last seen type decl in the provided lines.
    """
    m = _pick_last_match(TYPE_RE, lines)
    return m.group(2) if m else None


def _clean_param_type(t: str) -> str:
    """
    Given a raw param like:
      'final @Nonnull Map<String, Integer> foo'
    return:
      'Map<String, Integer>'
    """
    t = t.strip()
    if not t:
        return ""
    # remove annotations tokens
    t = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", t)
    # remove common modifiers
    t = re.sub(r"\bfinal\b\s+", "", t)
    # collapse whitespace
    t = _normalize_ws(t)

    # split tokens; attempt to drop trailing param name
    # Handle varargs: "String... args" => type is "String..."
    # Handle arrays: "String[] args" => type is "String[]"
    tokens = t.split(" ")
    if len(tokens) == 1:
        return tokens[0]

    # Heuristic: last token is usually variable name (may include commas? not in params)
    # But for lambdas / weird cases, this can fail.
    type_part = " ".join(tokens[:-1]).strip()
    if not type_part:
        return tokens[0]
    return type_part


def _normalize_param_list(params_raw: str) -> List[str]:
    params_raw = params_raw.strip()
    if not params_raw:
        return []
    # naive split on commas not inside <> (generics)
    out: List[str] = []
    buf = []
    depth = 0
    for ch in params_raw:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf).strip())

    return [_clean_param_type(x) for x in out if _clean_param_type(x)]


def _extract_method_from_context(context: Optional[str]) -> Optional[Tuple[str, List[str]]]:
    """
    Try to parse a method signature from diff hunk context (often includes signature).
    """
    if not context:
        return None
    line = _strip_inline_comments(context).strip()
    if not line:
        return None
    m = METHOD_RE.match(line)
    if not m:
        return None
    name = m.group("name")
    params = _normalize_param_list(m.group("params") or "")
    return name, params


def _extract_method_from_lines(lines: List[str]) -> Optional[Tuple[str, List[str]]]:
    """
    Scan lines for a Java method/ctor declaration (choose the last match).
    """
    last: Optional[Tuple[str, List[str]]] = None
    for ln in lines:
        s = _strip_inline_comments(ln)
        s = _normalize_ws(s)
        if not s:
            continue
        m = METHOD_RE.match(s)
        if not m:
            continue
        name = m.group("name")
        params = _normalize_param_list(m.group("params") or "")
        last = (name, params)
    return last


def _compose_container(
    path_fqcn: Optional[str],
    package_decl: Optional[str],
    nearest_type: Optional[str],
    file_class: Optional[str],
) -> Optional[str]:
    """
    Build a best-effort container:
      - Prefer package decl if found, else path-inferred package.
      - Prefer nearest type as inner/declared type when it differs from file class.
    """
    # Determine base package + outer class from path
    base_fqcn = path_fqcn
    base_pkg = None
    outer = None
    if base_fqcn and "." in base_fqcn:
        base_pkg, outer = base_fqcn.rsplit(".", 1)
    elif base_fqcn:
        outer = base_fqcn

    pkg = package_decl or base_pkg
    outer_class = file_class or outer

    if not outer_class:
        # fallback: if path_fqcn is full, use it
        if pkg and outer:
            outer_class = outer
        elif base_fqcn:
            return base_fqcn
        else:
            return None

    # inner heuristic
    if nearest_type and outer_class and nearest_type != outer_class:
        # likely an inner type or non-public type in same file
        container = f"{outer_class}.{nearest_type}"
    else:
        container = outer_class

    if pkg:
        return f"{pkg}.{container}"
    return container


def _confidence_java(
    has_path_fqcn: bool,
    has_package: bool,
    has_type: bool,
    has_method: bool,
    removed_count: int,
    added_count: int,
) -> float:
    """
    Java-focused heuristic confidence in (container#method(params)) being meaningful.
    """
    score = 0.0
    if removed_count > 0:
        score += 0.45
    if added_count > 0:
        score += 0.10
    if has_method:
        score += 0.20
    if has_type:
        score += 0.10
    if has_package or has_path_fqcn:
        score += 0.15
    return min(1.0, score)


def _git_show_cmd(fix_sha: Optional[str], file_path: str, old_start: int, old_len: int, context_lines: int = 20) -> Optional[str]:
    if not fix_sha:
        return None
    start = max(1, old_start - context_lines)
    end = max(start, old_start + max(old_len, 1) + context_lines)
    return f"git show {fix_sha}^:{file_path} | nl -ba | sed -n '{start},{end}p'"


@dataclass
class JavaCandidate:
    source_url: str
    repo: Optional[str]
    fix_sha: Optional[str]

    file_path: str
    old_start: int
    old_end: int
    old_len: int

    package: Optional[str]
    container: Optional[str]     # e.g., com.foo.Bar or com.foo.Bar.Inner
    method: Optional[str]        # e.g., readObject
    param_types: List[str]       # e.g., ["java.io.ObjectInputStream"]

    best_path: str               # e.g., com.foo.Bar#readObject(java.io.ObjectInputStream)
    confidence: float

    removed_line_count: int
    added_line_count: int

    git_show_cmd: Optional[str]


def iter_java_candidates(data: List[Dict[str, Any]], max_scan_lines: int = 80) -> List[JavaCandidate]:
    out: List[JavaCandidate] = []

    for analysis in data:
        source_url = analysis.get("source_url") or ""
        repo_field = analysis.get("repo")
        repo, fix_sha = _extract_repo_and_sha(source_url, repo_field)

        for fd in analysis.get("file_diffs") or []:
            file_path = fd.get("path") or ""
            if PurePosixPath(file_path).suffix.lower() != ".java":
                continue

            path_fqcn = _infer_fqcn_from_path(file_path)
            file_class = _file_basename_class(file_path)

            for h in fd.get("hunks") or []:
                old_start = _safe_int(h.get("old_start"), 0)
                old_len = _safe_int(h.get("old_len"), 0)
                old_end = max(old_start, old_start + max(old_len, 1) - 1)

                context = h.get("context") or ""
                near_context = h.get("near_context") or []
                removed = h.get("removed") or []
                added = h.get("added") or []

                # Remove clipped lines markers "..." from counts
                removed_count = sum(1 for x in removed if isinstance(x, str) and not x.startswith("..."))
                added_count = sum(1 for x in added if isinstance(x, str) and not x.startswith("..."))

                # Build scan window: context + tail of near_context + removed + added
                scan_lines: List[str] = []
                if context:
                    scan_lines.append(context)
                scan_lines.extend([x for x in near_context if isinstance(x, str)])
                scan_lines.extend([x for x in removed if isinstance(x, str)])
                scan_lines.extend([x for x in added if isinstance(x, str)])
                scan_lines = scan_lines[-max_scan_lines:]

                package_decl = _extract_package(scan_lines)
                nearest_type = _extract_nearest_type(scan_lines)

                method_ctx = _extract_method_from_context(context)
                method_line = method_ctx or _extract_method_from_lines(scan_lines)
                method_name = method_line[0] if method_line else None
                param_types = method_line[1] if method_line else []

                container = _compose_container(
                    path_fqcn=path_fqcn,
                    package_decl=package_decl,
                    nearest_type=nearest_type,
                    file_class=file_class,
                )

                if container and method_name:
                    if param_types:
                        best_path = f"{container}#{method_name}({', '.join(param_types)})"
                    else:
                        best_path = f"{container}#{method_name}"
                elif container:
                    best_path = container
                else:
                    # fallback
                    if method_name and param_types:
                        best_path = f"{file_path}#{method_name}({', '.join(param_types)})"
                    elif method_name:
                        best_path = f"{file_path}#{method_name}"
                    else:
                        best_path = file_path

                conf = _confidence_java(
                    has_path_fqcn=bool(path_fqcn),
                    has_package=bool(package_decl),
                    has_type=bool(nearest_type),
                    has_method=bool(method_name),
                    removed_count=removed_count,
                    added_count=added_count,
                )

                cmd = _git_show_cmd(fix_sha, file_path, old_start, old_len)

                out.append(
                    JavaCandidate(
                        source_url=source_url,
                        repo=repo,
                        fix_sha=fix_sha,
                        file_path=file_path,
                        old_start=old_start,
                        old_end=old_end,
                        old_len=old_len,
                        package=package_decl,
                        container=container,
                        method=method_name,
                        param_types=param_types,
                        best_path=best_path,
                        confidence=conf,
                        removed_line_count=removed_count,
                        added_line_count=added_count,
                        git_show_cmd=cmd,
                    )
                )

    return out


def group_candidates(cands: List[JavaCandidate]) -> List[JavaCandidate]:
    """
    Merge duplicates by (source_url, file_path, best_path).
    """
    m: Dict[Tuple[str, str, str], JavaCandidate] = {}
    for c in cands:
        key = (c.source_url, c.file_path, c.best_path)
        if key not in m:
            m[key] = c
        else:
            e = m[key]
            e.old_start = min(e.old_start, c.old_start)
            e.old_end = max(e.old_end, c.old_end)
            e.old_len = (e.old_end - e.old_start + 1)
            e.removed_line_count += c.removed_line_count
            e.added_line_count += c.added_line_count
            e.confidence = min(1.0, max(e.confidence, c.confidence) + 0.05)
            if e.git_show_cmd is None and c.git_show_cmd:
                e.git_show_cmd = c.git_show_cmd
    return list(m.values())


def main() -> int:
    ap = argparse.ArgumentParser(description="Guess Java vulnerable code paths from vuln_code_locator.py JSON output.")
    ap.add_argument("input_json", help="Path to vuln_code_locator.py results JSON file.")
    ap.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    ap.add_argument("--out", default=None, help="Write output to file (default: stdout).")
    ap.add_argument("--top", type=int, default=100, help="Max candidates to output.")
    ap.add_argument("--min-confidence", type=float, default=0.0, help="Filter out candidates below this confidence (0..1).")
    ap.add_argument("--group", action="store_true", help="Merge duplicates by (patch,file,best_path).")
    args = ap.parse_args()

    with open(args.input_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    cands = iter_java_candidates(data)
    if args.group:
        cands = group_candidates(cands)

    # Rank: confidence, removed lines (signal), then having a method
    cands.sort(
        key=lambda c: (c.confidence, c.removed_line_count, 1 if c.method else 0, c.added_line_count),
        reverse=True,
    )

    cands = [c for c in cands if c.confidence >= args.min_confidence][: max(0, args.top)]

    if args.format == "json":
        text = json.dumps([asdict(c) for c in cands], indent=2, ensure_ascii=False)
    else:
        lines: List[str] = []
        for i, c in enumerate(cands, start=1):
            lines.append("=" * 90)
            lines.append(f"[{i}] {c.best_path}")
            lines.append(f"  confidence: {c.confidence:.2f}  removed:{c.removed_line_count}  added:{c.added_line_count}")
            lines.append(f"  file: {c.file_path}")
            lines.append(f"  pre-fix lines: {c.old_start}-{c.old_end} (len={c.old_len})")
            if c.repo:
                lines.append(f"  repo: {c.repo}")
            if c.fix_sha:
                lines.append(f"  fix_sha: {c.fix_sha}")
            lines.append(f"  patch: {c.source_url}")
            if c.git_show_cmd:
                lines.append("  view pre-fix snippet (run inside repo clone):")
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