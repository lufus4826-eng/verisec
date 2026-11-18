#!/usr/bin/env python3
"""Deterministic Business-Logic Security & Dual-Gate CLI Engine for VeriSec v1.0 (stdlib only).

Subcommands:
  init            Initialize .bughunt/sec-<ts>/ session, network guard, fs-before.txt, worklog.md
  surface-map     Scan API routes/handlers, auth guards, external inputs, and 4 risk categories
  isolated-poc    Run PoC/test script with 100% outbound network isolation + secret redaction
  redact-output   Scrub keys, passwords, JWTs, and Bearer tokens from text/files/session logs
  verify          Enforce Gate 1 (Invariant Breach) & Gate 2 (Remediation + Non-Regression + Rollback)
  sandbox         Manage S/sandbox-fix, per-target checkpoints, redacted diff, and cleanliness check
  log             Update worklog.md Status line + append redacted 1-line entries atomically
  summary         Emit redacted Markdown tables & PoC snippets from verified session JSONs
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, field
from datetime import datetime, timezone
import difflib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


IGNORED_SCAN_DIRS = frozenset(
    {
        ".git",
        ".bughunt",
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "target",
        "bin",
        "obj",
        "dist",
        "build",
        ".gradle",
        ".idea",
        ".vs",
        "TestResults",
        "vendor",
        "coverage",
        ".next",
        ".nuxt",
        "out",
    }
)

TEST_DIR_NAMES = frozenset({"tests", "test", "__tests__", "spec", "specs", "benches", "pocs"})

SANDBOX_ALWAYS_EXCLUDE = frozenset(
    {
        ".git",
        ".bughunt",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".vs",
        "TestResults",
        ".idea",
        ".gradle",
    }
)

SNAPSHOT_FS_SKIP_DIRS = frozenset({".bughunt", ".git", "node_modules"})

EXT_LANG = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".cs": "C#",
    ".php": "PHP",
    ".rs": "Rust",
}

BINARY_EXTS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".tar",
        ".gz", ".bz2", ".xz", ".7z", ".whl", ".exe", ".dll", ".so", ".dylib",
        ".class", ".jar", ".pyc", ".pyo", ".o", ".a", ".wasm", ".ttf", ".woff",
        ".woff2", ".db", ".sqlite", ".sqlite3",
    }
)

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
POC_PREFIX = "VERISEC_POC:"

CONTROL_TEST_RE = re.compile(
    r"^(?:test_?|test(?=[A-Z])|Test[A-Za-z0-9_]*_?)?[Cc]ontrol(?:[^a-zA-Z]|$|(?=[A-Z]))"
    r"|\(control\)"
    r"|\bcontrol\s*:",
)
CONTROL_CAMEL_RE = re.compile(r"^(?:test|Test(?:R\d+H\d+|SEC\d+)?)Control")

CATEGORIES = (
    "IDOR_BOLA",
    "MISSING_AUTH_GUARD",
    "MASS_ASSIGNMENT",
    "RACE_DOUBLE_SPEND",
)


# ---------------------------------------------------------------------------
# Secret Redaction Engine (`redact-output`)
# ---------------------------------------------------------------------------

_SECRET_KEY_NAMES = (
    r"(?:password|passwd|pwd|secret|client_secret|jwt_secret|api_key|apikey|"
    r"api_token|access_token|refresh_token|private_key|auth_token|session_secret|"
    r"secret_key|bearer_token|signing_key|webhook_secret|encryption_key|db_pass|db_password)"
)

_REDACT_RULES: Tuple[Tuple[re.Pattern[str], Any], ...] = (
    # PEM private keys
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        lambda _m: "-----BEGIN PRIVATE KEY-----[REDACTED_KEY]-----END PRIVATE KEY-----",
    ),
    # Authorization: Bearer / Basic headers
    (
        re.compile(r"(?i)(\bAuthorization\s*:\s*Bearer\s+)([^\s\"'\r\n,;]+)"),
        lambda m: f"{m.group(1)}[REDACTED_TOKEN]" if "[REDACTED" not in m.group(2) else m.group(0),
    ),
    (
        re.compile(r"(?i)(\bAuthorization\s*:\s*Basic\s+)([A-Za-z0-9+/=]{8,})"),
        lambda m: f"{m.group(1)}[REDACTED_AUTH]",
    ),
    # Bare Bearer <jwt_or_long_token>
    (
        re.compile(
            r"(?i)(\bBearer\s+)(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[A-Za-z0-9_\-.~+/]{16,}=*)"
        ),
        lambda m: f"{m.group(1)}[REDACTED_TOKEN]" if "[REDACTED" not in m.group(2) else m.group(0),
    ),
    # Standalone JWTs
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        lambda _m: "eyJ...[REDACTED_JWT]",
    ),
    # Well-known API key prefixes
    (
        re.compile(
            r"\b(sk-(?:live-|test-|proj-)?|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|"
            r"xox[baprs]-|AKIA|AIza)[A-Za-z0-9_\-]{10,}\b"
        ),
        lambda m: f"{m.group(1)}[REDACTED_KEY]",
    ),
    # Connection strings with credentials: scheme://user:pass@host
    (
        re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?)://[^:\s/@\"']+:)([^@\s\"']+)(@)"
        ),
        lambda m: (
            f"{m.group(1)}[REDACTED_SECRET]{m.group(3)}"
            if "[REDACTED" not in m.group(2)
            else m.group(0)
        ),
    ),
    # JSON / Python dict / header quoted key-value secrets: "api_token": "value"
    (
        re.compile(
            rf"""(?i)(["']{_SECRET_KEY_NAMES}["']\s*:\s*["'])([^"'\r\n]{{4,}})(["'])"""
        ),
        lambda m: (
            f"{m.group(1)}[REDACTED_SECRET]{m.group(3)}"
            if "[REDACTED" not in m.group(2)
            else m.group(0)
        ),
    ),
    # Unquoted header / env / query-string / assignment secrets: password=foo or X-API-Key: foo
    (
        re.compile(
            rf"""(?i)(\b(?:x-api-key|{_SECRET_KEY_NAMES})\b\s*[:=]\s*["']?)([^\s"'&;,\r\n\}})]{{4,}})"""
        ),
        lambda m: (
            f"{m.group(1)}[REDACTED_SECRET]"
            if "[REDACTED" not in m.group(2) and not m.group(2).startswith("<")
            else m.group(0)
        ),
    ),
)


def redact_secrets(text: str) -> Tuple[str, int]:
    """Mask keys, passwords, JWTs, Bearer tokens, and connection secrets deterministically."""
    if not text:
        return text, 0
    total = 0
    out = text
    for pattern, repl in _REDACT_RULES:
        def _wrap(match: re.Match[str], fn: Any = repl) -> str:
            nonlocal total
            res = fn(match)
            if res != match.group(0):
                total += 1
            return res

        out = pattern.sub(_wrap, out)
    return out, total


def find_unredacted_secrets(text: str) -> List[str]:
    """Return list of rule descriptions if any unredacted secret pattern remains in text."""
    findings: List[str] = []
    scrubbed, count = redact_secrets(text)
    if count > 0 and scrubbed != text:
        for idx, (pat, _) in enumerate(_REDACT_RULES):
            for m in pat.finditer(text):
                # Check if rule actually changes the match
                _, c = redact_secrets(m.group(0))
                if c > 0:
                    findings.append(f"rule_{idx}: {trunc(m.group(0), 48)}")
                    if len(findings) >= 10:
                        return findings
    return findings


# ---------------------------------------------------------------------------
# Core Utilities & Isolation
# ---------------------------------------------------------------------------


def configure_stdio() -> None:
    """Ensure UTF-8 stdout/stderr on Windows without failing on redirected streams."""
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def trunc(text: str, max_len: int = 140) -> str:
    clean = " ".join(text.strip().split())
    if len(clean) <= max_len:
        return clean
    return clean[: max(0, max_len - 3)] + "..."


def sanitize_id(raw_id: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw_id.strip())
    if not clean or clean in (".", ".."):
        raise SystemExit(f"[vs.py] ERROR: Invalid target ID: {raw_id!r}")
    return clean


def is_control_name(name: str) -> bool:
    base = name.split("::")[-1].split(".")[-1].split("/")[-1].strip()
    return bool(CONTROL_TEST_RE.search(base) or CONTROL_CAMEL_RE.match(base))


def resolve_root(root_arg: Optional[str]) -> Path:
    root = Path(root_arg).resolve() if root_arg else Path.cwd().resolve()
    if not root.exists():
        raise SystemExit(f"[vs.py] ERROR: ROOT does not exist: {root}")
    return root


def resolve_session(s_arg: str, root_arg: Optional[str] = None) -> Tuple[Path, Path, str, Path]:
    """Resolve (ROOT, S_DIR, SNAME, CACHE_DIR) from --s argument."""
    s_path = Path(s_arg)
    if not s_path.is_absolute():
        base = resolve_root(root_arg)
        s_path = (base / s_path).resolve()
    else:
        s_path = s_path.resolve()

    if root_arg:
        root = resolve_root(root_arg)
    elif s_path.parent.name == ".bughunt":
        root = s_path.parent.parent.resolve()
    else:
        root = Path.cwd().resolve()

    cache_dir = root / ".bughunt" / ".cache"
    return root, s_path, s_path.name, cache_dir


def rel_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


NETGUARD_CODE = '''"""VeriSec 100% Outbound Network Isolation Guard (auto-loaded via PYTHONPATH)."""
import os
import socket

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0", ""}


def _extract_host(addr):
    if isinstance(addr, tuple) and addr:
        return str(addr[0]).strip("[]").lower()
    if isinstance(addr, str):
        return addr.strip("[]").lower()
    return ""


def _is_allowed_socket(sock, addr):
    if getattr(sock, "family", None) == getattr(socket, "AF_UNIX", object()):
        return True
    host = _extract_host(addr)
    return host in _ALLOWED_HOSTS


if os.environ.get("VERISEC_OFFLINE") == "1":
    _orig_connect = socket.socket.connect
    _orig_connect_ex = socket.socket.connect_ex
    _orig_create_connection = socket.create_connection
    _orig_getaddrinfo = socket.getaddrinfo

    def _guarded_connect(self, address):
        if not _is_allowed_socket(self, address):
            raise RuntimeError(f"VERISEC_NET_GUARD: Blocked external socket connect to {address!r}")
        return _orig_connect(self, address)

    def _guarded_connect_ex(self, address):
        if not _is_allowed_socket(self, address):
            raise RuntimeError(f"VERISEC_NET_GUARD: Blocked external socket connect_ex to {address!r}")
        return _orig_connect_ex(self, address)

    def _guarded_create_connection(address, *args, **kwargs):
        host = _extract_host(address)
        if host not in _ALLOWED_HOSTS:
            raise RuntimeError(f"VERISEC_NET_GUARD: Blocked external network connection to {address!r}")
        return _orig_create_connection(address, *args, **kwargs)

    def _guarded_getaddrinfo(host, port, *args, **kwargs):
        h = str(host or "").strip("[]").lower()
        if h not in _ALLOWED_HOSTS:
            raise RuntimeError(f"VERISEC_NET_GUARD: Blocked external DNS lookup for {host!r}")
        return _orig_getaddrinfo(host, port, *args, **kwargs)

    socket.socket.connect = _guarded_connect
    socket.socket.connect_ex = _guarded_connect_ex
    socket.create_connection = _guarded_create_connection
    socket.getaddrinfo = _guarded_getaddrinfo
'''


def ensure_netguard(s_dir: Path) -> Path:
    ng_dir = s_dir / "tmp" / "netguard"
    ng_dir.mkdir(parents=True, exist_ok=True)
    sc_file = ng_dir / "sitecustomize.py"
    if not sc_file.is_file():
        sc_file.write_text(NETGUARD_CODE, encoding="utf-8")
    return ng_dir


def build_isolated_env(
    s_dir: Path,
    cache_dir: Path,
    target_root: Optional[Path] = None,
    phase: str = "baseline",
    extra_env: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build 100% network-isolated environment with cache redirection and target root binding."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    ng_dir = ensure_netguard(s_dir)

    env = os.environ.copy()
    env.update(
        {
            "VERISEC_OFFLINE": "1",
            "VERISEC_PHASE": phase,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTEST_ADDOPTS": "-p no:cacheprovider",
            "MYPY_CACHE_DIR": str(cache_dir / "mypy"),
            "RUFF_CACHE_DIR": str(cache_dir / "ruff"),
            "HTTP_PROXY": "http://127.0.0.1:0",
            "HTTPS_PROXY": "http://127.0.0.1:0",
            "ALL_PROXY": "http://127.0.0.1:0",
            "http_proxy": "http://127.0.0.1:0",
            "https_proxy": "http://127.0.0.1:0",
            "all_proxy": "http://127.0.0.1:0",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "GOPROXY": "off",
            "GOCACHE": str(cache_dir / "go-build"),
            "GOLANGCI_LINT_CACHE": str(cache_dir / "golangci-lint"),
            "CARGO_TARGET_DIR": str(cache_dir / "cargo-target"),
            "CARGO_NET_OFFLINE": "true",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
            "npm_config_offline": "true",
            "npm_config_cache": str(cache_dir / "npm"),
            "NO_COLOR": "1",
            "FORCE_COLOR": "0",
            "TERM": "dumb",
        }
    )

    py_parts = [str(ng_dir.resolve())]
    if target_root is not None:
        t_str = str(target_root.resolve())
        env["VERISEC_TARGET_ROOT"] = t_str
        py_parts.append(t_str)
        prev_node = env.get("NODE_PATH", "")
        nm = str((target_root / "node_modules").resolve())
        env["NODE_PATH"] = f"{nm}{os.pathsep}{prev_node}" if prev_node else nm

    prev_py = env.get("PYTHONPATH", "")
    if prev_py:
        py_parts.append(prev_py)
    env["PYTHONPATH"] = os.pathsep.join(py_parts)

    if extra_env:
        env.update(extra_env)
    return env


def _split_cli_args(cmd_str: str) -> List[str]:
    """Split a command string preserving Windows backslashes and quotes."""
    if os.name != "nt":
        return shlex.split(cmd_str, posix=True)
    tokens: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    in_token = False
    i = 0
    n = len(cmd_str)
    while i < n:
        ch = cmd_str[i]
        if quote is not None:
            if ch == "\\" and quote == '"' and i + 1 < n and cmd_str[i + 1] == '"':
                buf.append('"')
                i += 2
                continue
            if ch == quote:
                quote = None
                i += 1
                continue
            buf.append(ch)
        else:
            if ch in (" ", "\t", "\r", "\n"):
                if in_token:
                    tokens.append("".join(buf))
                    buf.clear()
                    in_token = False
                i += 1
                continue
            in_token = True
            if ch in ('"', "'"):
                quote = ch
            else:
                buf.append(ch)
        i += 1
    if in_token:
        tokens.append("".join(buf))
    return tokens


def parse_cmd_tokens(raw_cmd: Sequence[str] | str) -> List[str]:
    if isinstance(raw_cmd, str):
        return _split_cli_args(raw_cmd)
    cmd = list(raw_cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if len(cmd) == 1 and " " in cmd[0] and not Path(cmd[0]).exists() and not shutil.which(cmd[0]):
        cmd = _split_cli_args(cmd[0])
    return cmd


def _resolve_bughunt_cmd_paths(cmd_tokens: List[str], root: Path) -> List[str]:
    """Resolve relative .bughunt/... paths against ROOT so commands work even when cwd=sandbox-fix."""
    resolved: List[str] = []
    for tok in cmd_tokens:
        norm = tok.replace("\\", "/")
        if norm.startswith(".bughunt/") or norm == ".bughunt":
            cand = (root / tok).resolve()
            if cand.exists():
                resolved.append(str(cand))
                continue
        resolved.append(tok)
    return resolved


def resolve_executable(cmd: List[str], cwd: Path, env: Dict[str, str]) -> List[str]:
    """Resolve Windows .cmd/.bat/.exe wrappers or Python executable safely."""
    if not cmd:
        return cmd
    exe = cmd[0]
    if exe in ("python", "python3") and os.name == "nt":
        return [sys.executable] + cmd[1:]
    if "/" in exe or "\\" in exe or exe.startswith("."):
        cand = cwd / exe
        if cand.is_file():
            return [str(cand)] + cmd[1:]
        if os.name == "nt" and not cand.suffix:
            for ext in (".bat", ".cmd", ".exe"):
                alt = cwd / (exe + ext)
                if alt.is_file():
                    return [str(alt)] + cmd[1:]
        return cmd
    resolved = shutil.which(exe, path=env.get("PATH"))
    if resolved:
        return [resolved] + cmd[1:]
    return cmd


# ---------------------------------------------------------------------------
# Snapshots & Cleanliness
# ---------------------------------------------------------------------------


def is_git_repo(root: Path) -> bool:
    if not shutil.which("git"):
        return False
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        return proc.returncode == 0 and proc.stdout.strip().lower() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def take_snapshot(root: Path, forced_mode: Optional[str] = None) -> Tuple[str, List[str]]:
    use_git = forced_mode == "git" or (forced_mode is None and is_git_repo(root))
    if use_git:
        try:
            proc = subprocess.run(
                ["git", "-c", "core.quotepath=false", "-C", str(root),
                 "status", "--porcelain", "--ignored", "--", "."],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if proc.returncode == 0:
                lines = [ln.rstrip("\r\n") for ln in proc.stdout.splitlines() if ln.strip()]
                return "git", lines
        except (OSError, subprocess.SubprocessError):
            pass

    entries: List[str] = []
    root_res = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root_res):
        dirnames[:] = sorted(d for d in dirnames if d not in SNAPSHOT_FS_SKIP_DIRS)
        dp = Path(dirpath)
        for fname in sorted(filenames):
            fp = dp / fname
            try:
                st = fp.lstat()
            except OSError:
                continue
            rel = fp.relative_to(root_res).as_posix()
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
            entries.append(f"{rel}\t{mtime}")
    entries.sort()
    return "fs", entries


def _is_bughunt_git_line(line: str) -> bool:
    path_part = line[3:].strip() if len(line) > 3 else line.strip()
    if " -> " in path_part:
        path_part = path_part.split(" -> ")[-1].strip()
    path_part = path_part.strip('"').replace("\\", "/")
    parts = [p for p in path_part.split("/") if p]
    return ".bughunt" in parts


def diff_snapshots(
    before_lines: List[str], after_lines: List[str], mode: str
) -> Dict[str, List[str]]:
    if mode == "git":
        b_filtered = [ln for ln in before_lines if not _is_bughunt_git_line(ln)]
        a_filtered = [ln for ln in after_lines if not _is_bughunt_git_line(ln)]
        b_set, a_set = set(b_filtered), set(a_filtered)
        return {
            "new_or_changed": [ln for ln in a_filtered if ln not in b_set],
            "resolved": [ln for ln in b_filtered if ln not in a_set],
        }

    def parse_fs(lines: Iterable[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for ln in lines:
            if "\t" in ln:
                p, ts = ln.split("\t", 1)
                if not p.startswith(".bughunt/"):
                    out[p] = ts
        return out

    b_map = parse_fs(before_lines)
    a_map = parse_fs(after_lines)
    return {
        "added": [p for p in sorted(a_map) if p not in b_map],
        "modified": [p for p in sorted(a_map) if p in b_map and a_map[p] != b_map[p]],
        "removed": [p for p in sorted(b_map) if p not in a_map],
    }


def _remove_readonly_and_rmtree(path: Path) -> None:
    def _onerror(func: Any, p: str, _exc: Any) -> None:
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_onerror)


def _clean_new_agent_caches(root: Path, diff: Dict[str, List[str]], snap_mode: str) -> List[str]:
    removed: List[str] = []
    if snap_mode == "git":
        candidates = []
        for ln in diff.get("new_or_changed", []):
            if len(ln) > 3 and ln[:2] in ("??", "!!"):
                candidates.append(ln[3:].strip().strip('"').replace("\\", "/"))
    else:
        candidates = diff.get("added", [])

    for rel_s in candidates:
        parts = [p for p in rel_s.split("/") if p]
        if ".bughunt" in parts:
            continue
        cache_idx = next((i for i, p in enumerate(parts) if p in ("__pycache__", ".pytest_cache")), None)
        if cache_idx is None:
            continue
        target = root / Path(*parts[: cache_idx + 1])
        if target.exists():
            if target.is_dir():
                _remove_readonly_and_rmtree(target)
            else:
                target.unlink(missing_ok=True)
            removed.append(rel_posix(target, root))
    return sorted(set(removed))


def find_prior_sessions(root: Path, current_sname: str) -> List[str]:
    bh_root = root / ".bughunt"
    if not bh_root.is_dir():
        return []
    out = [
        d.name for d in bh_root.iterdir()
        if d.is_dir() and d.name.startswith("sec-") and d.name != current_sname
    ]
    return sorted(out, reverse=True)


# ---------------------------------------------------------------------------
# Subcommand: init, log, redact-output
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    bh_root = root / ".bughunt"
    bh_root.mkdir(parents=True, exist_ok=True)
    cache_dir = bh_root / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    sname = f"sec-{stamp}"
    s_dir = bh_root / sname
    suffix = 1
    while s_dir.exists():
        sname = f"sec-{stamp}-{suffix}"
        s_dir = bh_root / sname
        suffix += 1

    for sub in ("pocs", "logs", "tmp"):
        (s_dir / sub).mkdir(parents=True, exist_ok=True)
    ensure_netguard(s_dir)

    snap_mode, snap_lines = take_snapshot(root)
    (s_dir / "logs" / "fs-before.txt").write_text(
        ("\n".join(snap_lines) + "\n") if snap_lines else "", encoding="utf-8"
    )
    (s_dir / "logs" / ".snapshot-mode").write_text(snap_mode + "\n", encoding="utf-8")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    worklog = s_dir / "worklog.md"
    worklog.write_text(
        f"Status: Initialized\n\n# VeriSec Worklog\n- Session: `{sname}` | Root: `{root}` | Started: `{now_iso}`\n",
        encoding="utf-8",
    )

    payload = {
        "S": rel_posix(s_dir, root),
        "SNAME": sname,
        "CACHE": rel_posix(cache_dir, root),
        "ROOT": str(root),
        "snapshot": snap_mode,
        "prior_sessions": find_prior_sessions(root, sname)[:5],
    }
    print(json.dumps(payload, ensure_ascii=False))
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    _, s_dir, _, _ = resolve_session(args.s, args.root)
    worklog = s_dir / "worklog.md"
    if not s_dir.is_dir():
        raise SystemExit(f"[vs.py] ERROR: Session directory missing: {s_dir}")

    lines = worklog.read_text(encoding="utf-8", errors="replace").splitlines() if worklog.is_file() else []
    if not lines:
        lines = ["Status: Initialized", "", "# VeriSec Worklog"]

    total_redactions = 0
    if args.status:
        clean_status, rc = redact_secrets(" ".join(args.status.strip().splitlines()))
        total_redactions += rc
        new_status = f"Status: {clean_status}"
        if lines[0].startswith("Status:"):
            lines[0] = new_status
        else:
            lines.insert(0, new_status)

    entries: List[str] = []
    if args.entry:
        for raw in args.entry:
            if raw == "-":
                entries.extend(ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip())
            elif raw.strip():
                entries.append(" ".join(raw.strip().splitlines()))
    if args.entry_file:
        ef = Path(args.entry_file)
        if ef.is_file():
            entries.extend(ln.strip() for ln in ef.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())

    ts = datetime.now().strftime("%H:%M:%S")
    for ent in entries:
        clean_ent, rc = redact_secrets(ent)
        total_redactions += rc
        prefix = "" if clean_ent.startswith("-") else "- "
        lines.append(f"{prefix}[{ts}] {clean_ent}")

    worklog.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"[vs log] status={lines[0].removeprefix('Status: ').strip()!r} "
        f"entries_added={len(entries)} redactions={total_redactions}"
    )
    return 0


def cmd_redact_output(args: argparse.Namespace) -> int:
    if args.scan:
        if not args.s:
            raise SystemExit("[vs.py] ERROR: --s is required with --scan")
        root, s_dir, _, _ = resolve_session(args.s, args.root)
        targets: List[Path] = []
        for sub in (s_dir / "logs",):
            if sub.is_dir():
                targets.extend(sorted(p for p in sub.iterdir() if p.is_file() and p.suffix in (".log", ".json", ".diff", ".md", ".txt")))
        for name in ("worklog.md", "sec-report.md"):
            fp = s_dir / name
            if fp.is_file():
                targets.append(fp)

        scrubbed_files = 0
        total_masked = 0
        remaining = 0
        for fp in targets:
            txt = fp.read_text(encoding="utf-8", errors="replace")
            clean_txt, count = redact_secrets(txt)
            if count > 0 and clean_txt != txt:
                fp.write_text(clean_txt, encoding="utf-8")
                scrubbed_files += 1
                total_masked += count
            if find_unredacted_secrets(clean_txt):
                remaining += 1

        status = "CLEAN" if remaining == 0 else "WARNING"
        print(
            f"[REDACT-SCAN] files={len(targets)} scrubbed_files={scrubbed_files} "
            f"masked={total_masked} unredacted_remaining={remaining} status={status}"
        )
        return 0 if remaining == 0 else 1

    if args.input_file:
        raw = Path(args.input_file).read_text(encoding="utf-8", errors="replace")
    elif args.text is not None:
        raw = args.text
    else:
        raw = sys.stdin.read()

    clean, count = redact_secrets(raw)
    if args.output_file:
        Path(args.output_file).write_text(clean, encoding="utf-8")
        print(f"[vs redact-output] output={args.output_file} redactions={count}")
    else:
        sys.stdout.write(clean)
        if clean and not clean.endswith("\n"):
            sys.stdout.write("\n")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: surface-map (API Surface & Auth Matrix Scanner)
# ---------------------------------------------------------------------------


@dataclass
class SurfaceEntry:
    file: str
    line: int
    symbol: str
    endpoint: str
    auth_guards: List[str]
    external_inputs: List[str]
    risk_tags: List[str]
    score: int
    evidence: str

    @property
    def risk_level(self) -> str:
        if self.score >= 80:
            return "HIGH"
        if self.score >= 50:
            return "MEDIUM"
        if self.risk_tags:
            return "LOW"
        return "GUARDED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "score": self.score,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "endpoint": self.endpoint,
            "auth_guards": self.auth_guards,
            "external_inputs": self.external_inputs,
            "risk_tags": self.risk_tags,
            "evidence": self.evidence,
        }


def _is_test_relpath(rel_posix_path: str) -> bool:
    parts = [p.lower() for p in rel_posix_path.split("/") if p]
    if any(p in TEST_DIR_NAMES for p in parts[:-1]):
        return True
    name = parts[-1] if parts else ""
    return (
        name.startswith("test_")
        or name.startswith("poc_")
        or name.endswith(("_test.py", "_test.go", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
    )


def _py_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _py_call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _py_call_name(node.func)
    return ""


_AUTH_DECORATOR_RE = re.compile(
    r"(?:auth|login|role|perm|admin|jwt|token|guard|session|acl|owner|require)", re.I
)
_ROUTE_DECORATOR_RE = re.compile(
    r"(?:^|\.)(?:route|get|post|put|patch|delete|api_view|websocket)$", re.I
)
_SENSITIVE_NAME_RE = re.compile(
    r"^(?:get|fetch|read|view|list|update|edit|patch|delete|remove|create|transfer|"
    r"withdraw|deposit|redeem|apply|claim|export|admin|purge|approve|checkout|pay|set)_",
    re.I,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:admin|export|purge|delete|ledger|invoice|account|profile|voucher|coupon|user|balance|role|config|audit)",
    re.I,
)
_PRIV_FIELD_RE = re.compile(
    r"""['"](?:role|is_admin|admin|balance|credit_limit|permissions|owner_id|tenant_id|verified|tier|plan)['"]"""
)
_OWNER_CHECK_RE = re.compile(
    r"\b(?:owner_id|tenant_id|org_id|created_by|author_id)\b|"
    r"(?:caller|current_user|user|actor)\s*[\[.]\s*['\"]?id['\"]?\s*\]?\s*[!=]=|"
    r"\b(?:check_owner|verify_owner|ensure_owner|require_owner)\b",
    re.I,
)
_AUTH_BODY_RE = re.compile(
    r"\b(?:require_auth|require_role|check_auth|verify_token|get_current_user|is_authenticated)\b|"
    r"(?:caller|current_user|user|actor)\s*[\[.]\s*['\"]?role['\"]?\s*\]?\s*[!=]=|"
    r"\bPermissionError\b|\bHTTPException\s*\(\s*(?:status_code\s*=\s*)?40[13]\b|\babort\s*\(\s*40[13]\b",
    re.I,
)
_INPUT_PARAM_RE = re.compile(
    r"(?:_id$|^id$|payload|data|body|form|json|params|kwargs|request|code|amount|qty|quantity|fields|updates)",
    re.I,
)
_ID_PARAM_RE = re.compile(r"(?:_id$|^id$)", re.I)


def _scan_python_surface(fp: Path, rel: str, text: str) -> List[SurfaceEntry]:
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError:
        return []

    src_lines = text.splitlines()
    file_has_priv_fields = bool(_PRIV_FIELD_RE.search(text))

    # First pass: inspect all top-level and class methods to know if sibling endpoints use auth guards
    func_records: List[Tuple[ast.AST, str, List[str], str]] = []

    def _exec_body(fn: ast.AST) -> str:
        assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        stmts = list(fn.body)
        if (
            stmts
            and isinstance(stmts[0], ast.Expr)
            and isinstance(stmts[0].value, ast.Constant)
            and isinstance(stmts[0].value.value, str)
        ):
            stmts = stmts[1:]
        if not stmts:
            return ""
        if hasattr(ast, "unparse"):
            return ast.unparse(ast.Module(body=stmts, type_ignores=[]))
        start = max(0, stmts[0].lineno - 1)
        end = min(len(src_lines), getattr(fn, "end_lineno", stmts[-1].lineno))
        return "\n".join(re.sub(r"#.*$", "", ln) for ln in src_lines[start:end])

    def _collect(node: ast.AST, prefix: str = "") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                _collect(child, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name.startswith("_"):
                    continue
                decs = [_py_call_name(d) for d in child.decorator_list]
                body_src = _exec_body(child)
                func_records.append((child, f"{prefix}{child.name}", decs, body_src))

    _collect(tree)

    any_sibling_auth = any(
        any(_AUTH_DECORATOR_RE.search(d) for d in decs) or bool(_AUTH_BODY_RE.search(bsrc))
        for _, _, decs, bsrc in func_records
    )

    entries: List[SurfaceEntry] = []
    for fn, sym, decs, body_src in func_records:
        assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        route_label = sym
        has_route_dec = False
        for d_ast, d_name in zip(fn.decorator_list, decs):
            if _ROUTE_DECORATOR_RE.search(d_name):
                has_route_dec = True
                if isinstance(d_ast, ast.Call) and d_ast.args:
                    arg0 = d_ast.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        route_label = f"{d_name.split('.')[-1].upper()} {arg0.value}"

        is_handler = has_route_dec or bool(_SENSITIVE_NAME_RE.match(fn.name))
        if not is_handler:
            continue

        arg_names = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs if a.arg not in ("self", "cls")]
        if fn.args.kwarg:
            arg_names.append(f"**{fn.args.kwarg.arg}")

        auth_guards: List[str] = []
        for d_name in decs:
            if _AUTH_DECORATOR_RE.search(d_name):
                auth_guards.append(f"@{d_name}")
        for d_ast in fn.args.defaults:
            dn = _py_call_name(d_ast)
            if dn and "Depends" in dn:
                auth_guards.append(ast.unparse(d_ast) if hasattr(ast, "unparse") else dn)
        if _AUTH_BODY_RE.search(body_src):
            auth_guards.append("body_auth_check")
        if _OWNER_CHECK_RE.search(body_src):
            auth_guards.append("owner_check")

        ext_inputs = [a for a in arg_names if _INPUT_PARAM_RE.search(a)]
        for pat in ("request.json", "request.form", "request.args", "request.data", "request.get_json"):
            if pat in body_src and pat not in ext_inputs:
                ext_inputs.append(pat)

        risk_tags: List[str] = []
        ev_parts: List[str] = []
        score = 20

        # 1. IDOR_BOLA check
        id_params = [a for a in arg_names if _ID_PARAM_RE.search(a) and not re.match(r"^(?:caller|current_user|actor)_id$", a, re.I)]
        has_lookup = bool(
            re.search(r"\[\s*(?:" + "|".join(re.escape(p) for p in id_params) + r")\s*\]", body_src)
            or re.search(r"\.(?:get|find|filter|filter_by|select)\s*\(", body_src)
            or "SELECT " in body_src.upper()
        ) if id_params else False
        if id_params and has_lookup and not _OWNER_CHECK_RE.search(body_src):
            risk_tags.append("IDOR_BOLA")
            score += 65
            ev_parts.append(f"lookup by {','.join(id_params)} without owner_id check")

        # 2. MISSING_AUTH_GUARD check
        has_explicit_auth = any(g != "owner_check" for g in auth_guards)
        if not has_explicit_auth and (
            (has_route_dec and any_sibling_auth)
            or (any_sibling_auth and _SENSITIVE_PATH_RE.search(sym))
            or re.match(r"^(?:admin|export|purge)_", fn.name, re.I)
        ):
            risk_tags.append("MISSING_AUTH_GUARD")
            score += 65
            ev_parts.append("no auth/role guard" + (" (siblings guarded)" if any_sibling_auth else ""))

        # 3. MASS_ASSIGNMENT check
        has_bulk_assign = bool(
            re.search(r"\.\s*update\s*\(\s*(?:payload|data|body|updates|kwargs|request\.json)", body_src)
            or re.search(r"for\s+\w+\s*,\s*\w+\s+in\s+\w+\.items\s*\(\s*\)\s*:", body_src)
            or re.search(r"\bsetattr\s*\(", body_src)
            or re.search(r"\*\*(?:payload|data|body|updates)\b", body_src)
        )
        has_whitelist = bool(
            re.search(r"\b(?:ALLOWED_FIELDS|WHITELIST|allowed|permitted_fields|safe_fields)\b", body_src, re.I)
        )
        if has_bulk_assign and not has_whitelist:
            risk_tags.append("MASS_ASSIGNMENT")
            score += 65 if file_has_priv_fields else 55
            ev_parts.append("unfiltered dict/attr update without field whitelist")

        # 4. RACE_DOUBLE_SPEND check
        has_state_check = bool(
            re.search(
                r"if\s+[^:\n]*\w*(?:balance|remaining|uses|stock|quota|credit|limit|used|redeemed)\w*[^:\n]*(?:>=|>|<=|<|==|not\s+)",
                body_src,
                re.I,
            )
        )
        has_state_mut = bool(
            re.search(
                r"\w*(?:balance|remaining|uses|stock|quota|credit|used|redeemed)\w*[^\n]*(?:-=|\+=|=\s*True|=\s*False)",
                body_src,
                re.I,
            )
        )
        has_lock = bool(
            re.search(r"\b(?:Lock|RLock|acquire|Semaphore|FOR\s+UPDATE|atomic|with\s+\w*lock)\b", body_src, re.I)
        )
        if has_state_check and has_state_mut and not has_lock:
            risk_tags.append("RACE_DOUBLE_SPEND")
            score += 70
            ev_parts.append("check-then-mutate balance/quota/uses without lock")

        if not risk_tags and not auth_guards:
            # Low-priority unguarded handler for visibility
            score = 35
            ev_parts.append("unguarded endpoint/handler")

        entries.append(
            SurfaceEntry(
                file=rel,
                line=fn.lineno,
                symbol=sym,
                endpoint=route_label,
                auth_guards=auth_guards or ["NONE"],
                external_inputs=ext_inputs or ["NONE"],
                risk_tags=risk_tags,
                score=min(100, score),
                evidence="; ".join(ev_parts) if ev_parts else "guarded",
            )
        )
    return entries


_BRACE_ROUTE_RE = re.compile(
    r"(?:(?:app|router|r|mux|api)\.(?:get|post|put|patch|delete|handlefunc)|"
    r"@(?:Get|Post|Put|Patch|Delete|RequestMapping|HttpGet|HttpPost|HttpPut|HttpDelete)|"
    r"#\[(?:get|post|put|patch|delete)\()",
    re.I,
)
_BRACE_FUNC_RE = re.compile(
    r"(?:(?:async\s+)?function\s+([A-Za-z_]\w*)|(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s+)?\(|"
    r"func\s+(?:\([^)]+\)\s*)?([A-Za-z_]\w*)\s*\(|"
    r"(?:public|private|protected|async|fn)\s+(?:[\w<>\[\]]+\s+)*([A-Za-z_]\w*)\s*\()"
)


def _scan_brace_surface(rel: str, text: str) -> List[SurfaceEntry]:
    lines = text.splitlines()
    entries: List[SurfaceEntry] = []
    any_auth_in_file = bool(
        re.search(r"\b(?:requireAuth|requireRole|authMiddleware|@PreAuthorize|\[Authorize\]|AuthGuard)\b", text)
    )

    i = 0
    while i < len(lines):
        ln = lines[i]
        m_route = _BRACE_ROUTE_RE.search(ln)
        m_func = _BRACE_FUNC_RE.search(ln)
        if not (m_route or m_func):
            i += 1
            continue

        window_end = min(len(lines), i + 28)
        block = re.sub(r"//[^\n]*|/\*[\s\S]*?\*/", "", "\n".join(lines[i:window_end]))
        sym = "route_handler"
        if m_func:
            sym = next((g for g in m_func.groups() if g), sym)
        endpoint = trunc(ln.strip(), 48) if m_route else sym

        auth_guards: List[str] = []
        for g_pat, g_lbl in (
            (r"\b(?:requireAuth|authMiddleware|authenticate)\b", "authMiddleware"),
            (r"\b(?:requireRole|hasRole|@PreAuthorize|\[Authorize[^\]]*\])\b", "roleGuard"),
            (r"\b(?:ownerId|owner_id|userId\s*!==|user\.id\s*!==)\b", "ownerCheck"),
        ):
            if re.search(g_pat, block):
                auth_guards.append(g_lbl)

        risk_tags: List[str] = []
        ev: List[str] = []
        score = 20

        if re.search(r"\b(?:params\.\w*id|req\.params\.\w+|id)\b", block, re.I) and re.search(
            r"(?:\.findById|\.get\(|SELECT\b|\[.*id.*\])", block, re.I
        ) and "ownerCheck" not in auth_guards:
            risk_tags.append("IDOR_BOLA")
            score += 65
            ev.append("ID lookup without ownerCheck")

        if m_route and not auth_guards and any_auth_in_file:
            risk_tags.append("MISSING_AUTH_GUARD")
            score += 65
            ev.append("route missing auth middleware")

        if re.search(r"(?:Object\.assign\s*\(|\.\.\.req\.body|\bUpdateModel\b|bindJSON)", block, re.I) and not re.search(
            r"\b(?:allowedFields|whitelist|pick\()\b", block, re.I
        ):
            risk_tags.append("MASS_ASSIGNMENT")
            score += 60
            ev.append("bulk request body assignment without whitelist")

        if re.search(r"if\s*\([^)]*(?:balance|remaining|stock|uses|quota)", block, re.I) and re.search(
            r"(?:-=|\+=|\.balance\s*=|\.used\s*=)", block, re.I
        ) and not re.search(r"\b(?:Mutex|Lock|FOR UPDATE|synchronized|atomic)\b", block, re.I):
            risk_tags.append("RACE_DOUBLE_SPEND")
            score += 65
            ev.append("check-then-mutate without mutex/lock")

        if risk_tags or m_route:
            entries.append(
                SurfaceEntry(
                    file=rel,
                    line=i + 1,
                    symbol=sym,
                    endpoint=endpoint,
                    auth_guards=auth_guards or ["NONE"],
                    external_inputs=["req/params"] if m_route else ["args"],
                    risk_tags=risk_tags,
                    score=min(100, score),
                    evidence="; ".join(ev) if ev else "guarded",
                )
            )
            i += 8
            continue
        i += 1
    return entries


def cmd_surface_map(args: argparse.Namespace) -> int:
    root = resolve_root(args.root)
    scan_root = (root / args.scope).resolve() if args.scope else root
    if not scan_root.exists():
        raise SystemExit(f"[vs.py] ERROR: scope does not exist: {scan_root}")

    all_entries: List[SurfaceEntry] = []
    scanned_files = 0
    for dirpath, dirnames, filenames in os.walk(scan_root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_SCAN_DIRS)
        dp = Path(dirpath)
        for fname in sorted(filenames):
            fp = dp / fname
            ext = fp.suffix.lower()
            if ext not in EXT_LANG:
                continue
            rel = rel_posix(fp, root)
            if _is_test_relpath(rel):
                continue
            try:
                if fp.stat().st_size > 1_000_000:
                    continue
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned_files += 1
            if ext == ".py":
                all_entries.extend(_scan_python_surface(fp, rel, text))
            else:
                all_entries.extend(_scan_brace_surface(rel, text))

    all_entries.sort(key=lambda e: (-e.score, -len(e.risk_tags), e.file, e.line))

    if args.s:
        _, s_dir, _, _ = resolve_session(args.s, args.root)
        logs_dir = s_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / "surface_map.json").write_text(
            json.dumps(
                {
                    "scanned_files": scanned_files,
                    "surface_count": len(all_entries),
                    "flagged_count": sum(1 for e in all_entries if e.risk_tags),
                    "entries": [e.to_dict() for e in all_entries],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    if args.json:
        print(
            json.dumps(
                {
                    "scanned_files": scanned_files,
                    "surface_count": len(all_entries),
                    "flagged_count": sum(1 for e in all_entries if e.risk_tags),
                    "entries": [e.to_dict() for e in all_entries[:30]],
                },
                ensure_ascii=False,
            )
        )
        return 0

    max_lines = max(8, int(args.max_lines))
    flagged = [e for e in all_entries if e.risk_tags]
    lines: List[str] = [
        f"[surface-map] scanned_files={scanned_files} handlers={len(all_entries)} "
        f"flagged={len(flagged)} top_shown={min(len(all_entries), max_lines - 3)}"
    ]
    if not all_entries:
        lines.append("No API routes or handler functions detected.")
    else:
        lines.append("RISK | TAGS | LOCATION | AUTH_GUARDS | INPUTS | EVIDENCE")
        for e in all_entries:
            if len(lines) >= max_lines - 1:
                break
            tags = ",".join(e.risk_tags) if e.risk_tags else "SAFE_CANDIDATE"
            guards = ",".join(e.auth_guards)
            inputs = ",".join(e.external_inputs[:3])
            lines.append(
                f"{e.risk_level}({e.score}) | {tags} | {e.file}:{e.line} ({e.symbol}) | "
                f"auth=[{guards}] | in=[{inputs}] | {trunc(e.evidence, 64)}"
            )
        if len(all_entries) > (max_lines - 3):
            lines.append(f"... ({len(all_entries) - (max_lines - 3)} more handlers saved in surface_map.json)")
    print("\n".join(lines[:max_lines]))
    return 0


# ---------------------------------------------------------------------------
# Subcommand: isolated-poc (100% Network Isolation + Redaction + PoC Digest)
# ---------------------------------------------------------------------------


@dataclass
class PocOutcome:
    id: str
    phase: str
    category: str
    runner: str
    exit_code: Optional[int]
    duration_s: float
    ran: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    control_status: str = "NOT_FOUND"  # PASS | FAIL | NOT_FOUND
    breach_status: str = "UNKNOWN"  # BREACH_CONFIRMED | BREACH_BLOCKED | CONTROL_FAILED | HARNESS_BROKEN
    network_isolated: bool = True
    harness_signals: List[str] = field(default_factory=list)
    detail: str = ""
    redactions: int = 0
    log_path: str = ""
    cmd: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "phase": self.phase,
            "category": self.category,
            "runner": self.runner,
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 3),
            "ran": self.ran,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "control_status": self.control_status,
            "breach_status": self.breach_status,
            "network_isolated": self.network_isolated,
            "harness_signals": self.harness_signals,
            "detail": self.detail,
            "redactions": self.redactions,
            "log_path": self.log_path,
            "cmd": self.cmd,
        }


def _detect_runner(cmd: Optional[Sequence[str]], text: str) -> str:
    if f"\n{POC_PREFIX}" in f"\n{text}":
        return "verisec_json"
    if cmd:
        joined = " ".join(cmd).lower()
        base0 = Path(cmd[0]).name.lower()
        if "pytest" in joined:
            return "pytest"
        if "unittest" in joined:
            return "unittest"
        if "vitest" in joined:
            return "vitest"
        if "jest" in joined:
            return "jest"
        if base0.startswith("node"):
            return "node"
        if base0 == "go" or base0.startswith("go."):
            return "go"
    if "test session starts" in text or re.search(r"^collected \d+ items", text, re.M):
        return "pytest"
    if re.search(r"^Ran \d+ tests? in [\d.]+s", text, re.M):
        return "unittest"
    if "TAP version" in text or re.search(r"^(?:#|[ℹi])\s+tests\s+\d+", text, re.M):
        return "node"
    if re.search(r"^=== RUN\s+", text, re.M) or re.search(r"^--- (PASS|FAIL):\s+", text, re.M):
        return "go"
    return "generic"


def _update_control(res: PocOutcome, name: str, passed: bool) -> None:
    if not is_control_name(name):
        return
    if not passed:
        res.control_status = "FAIL"
    elif res.control_status != "FAIL":
        res.control_status = "PASS"


def _evaluate_poc_output(
    raw_clean_redacted: str,
    target_id: str,
    phase: str,
    category: str,
    exit_code: int,
    duration_s: float,
    cmd: List[str],
    log_path_rel: str,
    redactions: int,
) -> PocOutcome:
    runner = _detect_runner(cmd, raw_clean_redacted)
    out = PocOutcome(
        id=target_id,
        phase=phase,
        category=category,
        runner=runner,
        exit_code=exit_code,
        duration_s=duration_s,
        log_path=log_path_rel,
        redactions=redactions,
        cmd=cmd,
    )

    if "VERISEC_NET_GUARD:" in raw_clean_redacted:
        out.network_isolated = False
        out.harness_signals.append("VERISEC_NET_GUARD triggered (external network attempted)")

    if "[vs.py] TIMEOUT" in raw_clean_redacted or exit_code == 124:
        out.harness_signals.append("command timeout")
        out.breach_status = "HARNESS_BROKEN"
        return out
    if "[vs.py] EXEC_ERROR" in raw_clean_redacted or exit_code == 127:
        out.harness_signals.append("command launch error")
        out.breach_status = "HARNESS_BROKEN"
        return out

    # Check common harness breakdown signals
    for pat, lbl in (
        (r"\bSyntaxError:", "SyntaxError"),
        (r"\bIndentationError:", "IndentationError"),
        (r"\bModuleNotFoundError:", "ModuleNotFoundError"),
        (r"\bImportError:", "ImportError"),
        (r"\bMODULE_NOT_FOUND\b", "MODULE_NOT_FOUND"),
        (r"\bERR_MODULE_NOT_FOUND\b", "ERR_MODULE_NOT_FOUND"),
    ):
        if re.search(pat, raw_clean_redacted):
            out.harness_signals.append(lbl)

    # Mode A: VERISEC_POC:{...}
    poc_records: List[Dict[str, Any]] = []
    for ln in raw_clean_redacted.splitlines():
        s = ln.strip()
        if s.startswith(POC_PREFIX):
            try:
                poc_records.append(json.loads(s[len(POC_PREFIX) :].strip()))
            except json.JSONDecodeError:
                out.harness_signals.append("invalid VERISEC_POC JSON")

    if poc_records:
        rec = poc_records[-1]
        if rec.get("category"):
            out.category = str(rec["category"])
        ctrl_raw = str(rec.get("control_authorized", "FAIL")).upper()
        out.control_status = "PASS" if ctrl_raw in ("PASS", "TRUE", "OK") else "FAIL"
        if rec.get("network_isolated") is False:
            out.network_isolated = False
            out.harness_signals.append("PoC reported network_isolated=false")
        breach_flag = bool(rec.get("breach_detected"))
        out.ran = int(rec.get("ran", 2))
        out.passed = out.ran if (out.control_status == "PASS" and not breach_flag) else (1 if out.control_status == "PASS" else 0)
        out.failed = 1 if breach_flag else (1 if out.control_status == "FAIL" else 0)
        out.detail = trunc(str(rec.get("details", "")), 140)
        if out.harness_signals:
            out.breach_status = "HARNESS_BROKEN"
        elif out.control_status != "PASS":
            out.breach_status = "CONTROL_FAILED"
        elif breach_flag:
            out.breach_status = "BREACH_CONFIRMED"
        else:
            out.breach_status = "BREACH_BLOCKED"
        return out

    # Mode B: Standard Test Runner Logs
    lines = raw_clean_redacted.splitlines()
    fail_snippets: List[str] = []

    if runner == "unittest":
        for ln in lines:
            m = re.match(r"^(\S+)\s+\([^)]+\)\s+\.\.\.\s+(ok|FAIL|ERROR|skipped\b.*)$", ln)
            if m:
                _update_control(out, m.group(1), m.group(2) == "ok")
            m_hdr = re.match(r"^(FAIL|ERROR):\s+(\S+)\s+\(([^)]+)\)", ln)
            if m_hdr:
                _update_control(out, m_hdr.group(2), False)
        m_ran = re.search(r"Ran\s+(\d+)\s+tests?\s+in\s+[\d.]+s", raw_clean_redacted)
        if m_ran:
            out.ran = int(m_ran.group(1))
        m_fail = re.search(r"FAILED\s+\(([^)]+)\)", raw_clean_redacted)
        if m_fail:
            parts = m_fail.group(1)
            mf = re.search(r"failures=(\d+)", parts)
            me = re.search(r"errors=(\d+)", parts)
            ms = re.search(r"skipped=(\d+)", parts)
            out.failed = int(mf.group(1)) if mf else 0
            out.errors = int(me.group(1)) if me else 0
            skipped = int(ms.group(1)) if ms else 0
            out.passed = max(0, out.ran - out.failed - out.errors - skipped)
        elif re.search(r"^OK(?:\s+\(.*\))?$", raw_clean_redacted, re.M):
            out.passed = out.ran
        for blk in re.split(r"^={70}$", raw_clean_redacted, flags=re.M):
            blk_s = re.split(r"^-{70}\r?\nRan\s+\d+\s+tests?", blk, maxsplit=1, flags=re.M)[0].strip()
            if blk_s.startswith("FAIL:") or blk_s.startswith("ERROR:"):
                blines = [l for l in blk_s.splitlines() if l.strip()]
                if blines:
                    fail_snippets.append(trunc(f"{blines[0]} -> {blines[-1]}", 140))
                if blk_s.startswith("ERROR:") and (
                    "unittest.loader" in blines[0]
                    or "setUpClass" in blines[0]
                    or "setUpModule" in blines[0]
                    or "tearDownClass" in blines[0]
                    or re.search(r": setUp \(", blines[0])
                ):
                    out.harness_signals.append("unittest setup/loader error")

    elif runner == "pytest":
        for ln in lines:
            m = re.match(r"^(\S+::.+?)\s+(PASSED|FAILED|ERROR|SKIPPED)(?:\s+\[\s*\d+%\])?\s*$", ln)
            if m:
                _update_control(out, m.group(1), m.group(2) == "PASSED")
            m_sum = re.match(r"^(FAILED|ERROR)\s+(\S+::.+?)(?:\s+-\s+.*)?$", ln)
            if m_sum:
                _update_control(out, m_sum.group(2), False)
            m_e = re.match(r"^E\s{2,}(.+)$", ln)
            if m_e and len(fail_snippets) < 2:
                fail_snippets.append(trunc(m_e.group(1), 140))
        sum_matches = re.findall(
            r"^(?:=+\s*)?(\d+\s+(?:passed|failed|errors?|skipped).*?)\s+in\s+[\d.]+s(?:\s*=+)?$",
            raw_clean_redacted,
            re.M | re.I,
        )
        if sum_matches:
            for cnt, kind in re.findall(r"(\d+)\s+(passed|failed|errors?)", sum_matches[-1], re.I):
                c = int(cnt)
                k = kind.lower()
                if k == "passed":
                    out.passed = c
                elif k == "failed":
                    out.failed = c
                elif k.startswith("error"):
                    out.errors = c
        out.ran = max(out.ran, out.passed + out.failed + out.errors)
        if exit_code in (2, 3, 4, 5):
            out.harness_signals.append(f"pytest exit={exit_code}")

    elif runner == "node":
        for pat, attr in (
            (r"^(?:#|[ℹi])\s+tests\s+(\d+)", "ran"),
            (r"^(?:#|[ℹi])\s+pass\s+(\d+)", "passed"),
            (r"^(?:#|[ℹi])\s+fail\s+(\d+)", "failed"),
        ):
            ms = re.findall(pat, raw_clean_redacted, re.M)
            if ms:
                setattr(out, attr, int(ms[-1]))
        for ln in lines:
            m_tap = re.match(r"^\s*(not )?ok\s+\d+\s+-\s+(.+)$", ln)
            if m_tap:
                _update_control(out, m_tap.group(2).strip(), not bool(m_tap.group(1)))
                if m_tap.group(1) and len(fail_snippets) < 2:
                    fail_snippets.append(trunc(ln.strip(), 140))
            m_spec = re.match(r"^\s*([✔✖])\s+(.+?)(?:\s+\([\d.]+ms\))?$", ln)
            if m_spec:
                _update_control(out, m_spec.group(2).strip(), m_spec.group(1) == "✔")
        if out.ran == 0:
            out.ran = out.passed + out.failed

    elif runner == "go":
        for ln in lines:
            m = re.match(r"^--- (PASS|FAIL):\s+(\S+)", ln)
            if m:
                out.ran += 1
                if m.group(1) == "PASS":
                    out.passed += 1
                else:
                    out.failed += 1
                    fail_snippets.append(trunc(ln, 140))
                _update_control(out, m.group(2), m.group(1) == "PASS")
        if "[build failed]" in raw_clean_redacted:
            out.harness_signals.append("go build failed")

    else:
        out.ran = 1
        if exit_code == 0:
            out.passed = 1
        else:
            out.failed = 1
            non_empty = [ln.strip() for ln in lines if ln.strip()]
            if non_empty:
                fail_snippets.append(trunc(non_empty[-1], 140))

    if out.ran == 0:
        out.harness_signals.append("ran 0 tests")

    out.detail = fail_snippets[0] if fail_snippets else (
        "All control & security invariant checks passed" if (out.failed == 0 and out.errors == 0) else f"exit={exit_code}"
    )

    if out.harness_signals:
        out.breach_status = "HARNESS_BROKEN"
    elif out.control_status == "FAIL":
        out.breach_status = "CONTROL_FAILED"
    elif out.errors > 0 and out.failed == 0:
        out.harness_signals.append(f"unexpected test error count={out.errors}")
        out.breach_status = "HARNESS_BROKEN"
    elif out.control_status == "NOT_FOUND" and runner in ("unittest", "pytest", "node", "go"):
        out.harness_signals.append("missing passing control test (test_control_*)")
        out.breach_status = "HARNESS_BROKEN"
    elif (out.failed > 0 or out.errors > 0) and out.ran > 0:
        out.breach_status = "BREACH_CONFIRMED"
    elif exit_code == 0 and out.failed == 0 and out.errors == 0 and out.ran > 0:
        out.breach_status = "BREACH_BLOCKED"
    else:
        out.harness_signals.append(f"unexpected exit={exit_code}")
        out.breach_status = "HARNESS_BROKEN"

    return out


def _execute_isolated_poc(
    root: Path,
    s_dir: Path,
    cache_dir: Path,
    target_id: str,
    phase: str,
    category: str,
    cmd_tokens: List[str],
    cwd_arg: Optional[str],
    timeout_s: int,
) -> Tuple[int, PocOutcome, str]:
    target_root = (s_dir / "sandbox-fix") if phase == "remediation" else root
    if phase == "remediation" and not target_root.is_dir():
        raise SystemExit(f"[vs.py] ERROR: {target_root} not found; run sandbox --mode fix first")

    if cwd_arg:
        cwd = Path(cwd_arg)
        if not cwd.is_absolute():
            cwd = (root / cwd).resolve()
    else:
        cwd = target_root

    resolved_tokens = _resolve_bughunt_cmd_paths(cmd_tokens, root)
    env = build_isolated_env(s_dir, cache_dir, target_root=target_root, phase=phase)
    resolved_cmd = resolve_executable(resolved_tokens, cwd, env)

    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            resolved_cmd,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
        duration = time.monotonic() - t0
        raw_out = proc.stdout or ""
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - t0
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        raw_out = partial + f"\n[vs.py] TIMEOUT after {timeout_s}s\n"
        rc = 124
    except FileNotFoundError as exc:
        duration = time.monotonic() - t0
        raw_out = f"[vs.py] EXEC_ERROR: command not found: {resolved_tokens[0]} ({exc})\n"
        rc = 127
    except OSError as exc:
        duration = time.monotonic() - t0
        raw_out = f"[vs.py] EXEC_ERROR: {exc}\n"
        rc = 126

    clean_out = strip_ansi(raw_out)
    redacted_out, red_count = redact_secrets(clean_out)

    log_file = s_dir / "logs" / f"{target_id}_{phase}.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.write_text(redacted_out.rstrip() + f"\nexit={rc}\n", encoding="utf-8")

    outcome = _evaluate_poc_output(
        raw_clean_redacted=redacted_out,
        target_id=target_id,
        phase=phase,
        category=category,
        exit_code=rc,
        duration_s=duration,
        cmd=resolved_tokens,
        log_path_rel=rel_posix(log_file, root),
        redactions=red_count,
    )
    json_file = s_dir / "logs" / f"{target_id}_{phase}.json"
    json_file.write_text(json.dumps(outcome.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    net_str = "ENFORCED (0 external socket calls)" if outcome.network_isolated else "VIOLATION DETECTED"
    harness_str = "OK (0 breakdown signals)" if not outcome.harness_signals else "BROKEN -> " + "; ".join(outcome.harness_signals[:3])
    digest_lines = [
        f"[POC] id={outcome.id} phase={outcome.phase} category={outcome.category} exit={rc} duration={outcome.duration_s:.2f}s",
        f"control_authorized: {outcome.control_status} | breach_status: {outcome.breach_status}",
        f"network_isolation: {net_str} | redactions: {outcome.redactions} masked",
        f"counts: ran={outcome.ran} passed={outcome.passed} failed={outcome.failed} errors={outcome.errors}",
        f"harness: {harness_str}",
        f"detail: {outcome.detail or '-'}",
        f"log: {outcome.log_path} (redacted)",
    ]
    return rc, outcome, "\n".join(digest_lines[:10])


def cmd_isolated_poc(args: argparse.Namespace) -> int:
    root, s_dir, _, cache_dir = resolve_session(args.s, args.root)
    tid = sanitize_id(args.id)
    cmd_tokens = parse_cmd_tokens(args.cmd)
    if not cmd_tokens:
        raise SystemExit("[vs.py] ERROR: No PoC command provided after --")
    rc, outcome, digest = _execute_isolated_poc(
        root=root,
        s_dir=s_dir,
        cache_dir=cache_dir,
        target_id=tid,
        phase=args.phase,
        category=args.category,
        cmd_tokens=cmd_tokens,
        cwd_arg=args.cwd,
        timeout_s=int(args.timeout),
    )
    print(digest)
    if outcome.breach_status == "HARNESS_BROKEN":
        return 2
    return 0


# ---------------------------------------------------------------------------
# Subcommand: verify (Dual Gate Architecture + Checkpoint Auto-Rollback)
# ---------------------------------------------------------------------------


def _checkpoint_dir(s_dir: Path, name: str) -> Path:
    return s_dir / "tmp" / "checkpoints" / sanitize_id(name)


def _compute_sandbox_exclusions(root: Path, extra: Sequence[str]) -> Tuple[set[str], set[str]]:
    global_excl = set(SANDBOX_ALWAYS_EXCLUDE)
    root_excl: set[str] = set()
    if (root / "Cargo.toml").is_file():
        root_excl.add("target")
    if (root / "pom.xml").is_file() or any((root / f).is_file() for f in ("build.gradle", "build.gradle.kts")):
        root_excl.update({"target", "build", "out"})
    if any(root.glob("*.sln")) or any(root.glob("*.csproj")):
        global_excl.update({"bin", "obj"})
    for item in extra:
        c = item.strip().strip("/\\")
        if c and c != "vendor":
            global_excl.add(c)
    global_excl.discard("vendor")
    root_excl.discard("vendor")
    return global_excl, root_excl


def _copy_project_tree(root: Path, dest: Path, global_excl: set[str], root_excl: set[str]) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    root_res = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root_res):
        dp = Path(dirpath)
        rel_dir = dp.relative_to(root_res)
        at_root = rel_dir == Path(".")
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in global_excl and not (at_root and d in root_excl) and not ((dp / d).is_symlink() and not (dp / d).exists())
        )
        out_dir = dest if at_root else (dest / rel_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for fname in sorted(filenames):
            src_f = dp / fname
            dst_f = out_dir / fname
            try:
                if src_f.is_symlink() and not src_f.exists():
                    continue
                shutil.copy2(src_f, dst_f, follow_symlinks=True)
                copied += 1
            except OSError:
                continue
    return copied


def _save_sandbox_checkpoint(root: Path, s_dir: Path, name: str) -> Tuple[Path, int]:
    fix_dir = s_dir / "sandbox-fix"
    if not fix_dir.is_dir():
        raise SystemExit(f"[vs.py] ERROR: {fix_dir} not found; run sandbox --mode fix first")
    dest = _checkpoint_dir(s_dir, name)
    if dest.exists():
        _remove_readonly_and_rmtree(dest)
    global_excl, root_excl = _compute_sandbox_exclusions(root, [])
    copied = _copy_project_tree(fix_dir, dest, global_excl, root_excl)
    return dest, copied


def _restore_sandbox_from(root: Path, s_dir: Path, src_dir: Path) -> int:
    fix_dir = s_dir / "sandbox-fix"
    if fix_dir.exists():
        _remove_readonly_and_rmtree(fix_dir)
    global_excl, root_excl = _compute_sandbox_exclusions(root, [])
    return _copy_project_tree(src_dir, fix_dir, global_excl, root_excl)


def _run_suite_in_sandbox(
    root: Path,
    s_dir: Path,
    cache_dir: Path,
    tid: str,
    test_cmd_str: str,
    cwd_arg: Optional[str],
    timeout_s: int,
) -> Tuple[bool, str, int]:
    fix_dir = s_dir / "sandbox-fix"
    cwd = (root / cwd_arg).resolve() if cwd_arg else fix_dir
    tokens = _resolve_bughunt_cmd_paths(parse_cmd_tokens(test_cmd_str), root)
    env = build_isolated_env(s_dir, cache_dir, target_root=fix_dir, phase="remediation")
    resolved = resolve_executable(tokens, cwd, env)
    try:
        proc = subprocess.run(
            resolved,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
        raw = strip_ansi(proc.stdout or "")
        red_out, red_cnt = redact_secrets(raw)
        log_path = s_dir / "logs" / f"{tid}_suite.log"
        log_path.write_text(red_out.rstrip() + f"\nexit={proc.returncode}\n", encoding="utf-8")
        if proc.returncode == 0 and "VERISEC_NET_GUARD:" not in red_out:
            return True, f"PASS (exit=0, redactions={red_cnt})", red_cnt
        tail = [ln.strip() for ln in red_out.splitlines() if ln.strip()][-2:]
        return False, f"FAIL (exit={proc.returncode}): {trunc(' | '.join(tail), 100)}", red_cnt
    except Exception as exc:
        return False, f"EXEC_ERROR: {trunc(str(exc), 100)}", 0


def cmd_verify(args: argparse.Namespace) -> int:
    root, s_dir, _, cache_dir = resolve_session(args.s, args.root)
    tid = sanitize_id(args.id)

    base_json = s_dir / "logs" / f"{tid}_baseline.json"
    if not base_json.is_file():
        raise SystemExit(f"[vs.py] ERROR: Baseline PoC missing: {base_json}")
    base_data = json.loads(base_json.read_text(encoding="utf-8"))
    category = base_data.get("category", args.category)

    # Gate 1 evaluation
    g1_ctrl = base_data.get("control_status") == "PASS"
    g1_net = bool(base_data.get("network_isolated", False))
    g1_harness = not bool(base_data.get("harness_signals"))
    b_status = base_data.get("breach_status", "UNKNOWN")

    if not g1_harness or b_status == "HARNESS_BROKEN":
        verdict = "REJECTED_GATE1_HARNESS"
        reason = "; ".join(base_data.get("harness_signals") or ["harness broken"])
        gate1_pass = False
    elif not g1_net:
        verdict = "REJECTED_GATE1_NETWORK"
        reason = "External network call attempted in baseline PoC"
        gate1_pass = False
    elif not g1_ctrl or b_status == "CONTROL_FAILED":
        verdict = "REJECTED_GATE1_CONTROL_FAIL"
        reason = "Authorized control case failed on unpatched baseline"
        gate1_pass = False
    elif b_status == "BREACH_BLOCKED":
        verdict = "REFUTED_SAFE"
        reason = "Authorized control passed and baseline already blocked unauthorized action"
        gate1_pass = False
    elif b_status == "BREACH_CONFIRMED":
        verdict = "GATE1_BREACH_CONFIRMED"
        reason = "Authorized control passed and boundary breach proven in isolated baseline"
        gate1_pass = True
    else:
        verdict = "REJECTED_GATE1_UNKNOWN"
        reason = f"Unexpected baseline breach_status={b_status}"
        gate1_pass = False

    if not gate1_pass or args.gate1_only:
        payload = {
            "id": tid,
            "category": category,
            "verdict": verdict,
            "reason": reason,
            "gate1_pass": gate1_pass,
            "gate2_pass": None,
            "baseline": base_data,
            "remediation": None,
            "suite_status": "N/A",
            "rollback_action": "NONE",
            "redactions": base_data.get("redactions", 0),
        }
        (s_dir / "logs" / f"{tid}_verify.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(
            "\n".join(
                [
                    f"[VERIFY] id={tid} category={category} verdict={verdict}",
                    f"Gate 1 (Invariant Breach): {'PASS' if gate1_pass else 'FAIL'} ({reason})",
                ]
            )
        )
        return 0 if verdict in ("GATE1_BREACH_CONFIRMED", "REFUTED_SAFE") else 1

    # Gate 2 evaluation in S/sandbox-fix
    rem_tokens = (
        parse_cmd_tokens(args.poc_cmd)
        if args.poc_cmd
        else list(base_data.get("cmd", []))
    )
    if not rem_tokens:
        raise SystemExit("[vs.py] ERROR: No PoC command found in baseline JSON or --poc-cmd")

    _, rem_outcome, _ = _execute_isolated_poc(
        root=root,
        s_dir=s_dir,
        cache_dir=cache_dir,
        target_id=tid,
        phase="remediation",
        category=category,
        cmd_tokens=rem_tokens,
        cwd_arg=args.cwd,
        timeout_s=int(args.timeout),
    )

    suite_ok = True
    suite_detail = "SKIPPED (no --test-cmd)"
    suite_red = 0
    if args.test_cmd:
        suite_ok, suite_detail, suite_red = _run_suite_in_sandbox(
            root, s_dir, cache_dir, tid, args.test_cmd, args.cwd, int(args.timeout)
        )

    total_red = int(base_data.get("redactions", 0)) + rem_outcome.redactions + suite_red

    # Check secret cleanliness across this target's logs
    rem_log = (s_dir / "logs" / f"{tid}_remediation.log")
    rem_txt = rem_log.read_text(encoding="utf-8", errors="replace") if rem_log.is_file() else ""
    unredacted = find_unredacted_secrets(rem_txt)

    if rem_outcome.harness_signals or not rem_outcome.network_isolated:
        verdict = "REJECTED_REMEDIATION_HARNESS"
        reason = "; ".join(rem_outcome.harness_signals or ["network isolation failure"])
        gate2_pass = False
    elif rem_outcome.control_status != "PASS":
        verdict = "REJECTED_CONTROL_BROKEN"
        reason = "Patch broke authorized control request (over-strict authorization guard)"
        gate2_pass = False
    elif rem_outcome.breach_status != "BREACH_BLOCKED":
        verdict = "REJECTED_INCOMPLETE_PATCH"
        reason = "Unauthorized/boundary breach still succeeds after patch"
        gate2_pass = False
    elif not suite_ok:
        verdict = "REJECTED_TEST_REGRESSION"
        reason = f"Existing project test suite failed: {suite_detail}"
        gate2_pass = False
    elif unredacted:
        verdict = "REJECTED_SECRET_LEAK"
        reason = f"Unredacted secret found in log: {unredacted[0]}"
        gate2_pass = False
    else:
        verdict = "CONFIRMED_REMEDIATED"
        reason = "Breach blocked, authorized control PASS, existing suite PASS, 0 unredacted secrets"
        gate2_pass = True

    rollback_action = "NONE"
    if gate2_pass:
        _save_sandbox_checkpoint(root, s_dir, "_last_accepted")
    elif args.auto_rollback:
        ckpt = _checkpoint_dir(s_dir, tid)
        last_acc = _checkpoint_dir(s_dir, "_last_accepted")
        if ckpt.is_dir():
            _restore_sandbox_from(root, s_dir, ckpt)
            rollback_action = f"AUTO_RESTORED (checkpoint:{tid})"
        elif last_acc.is_dir():
            _restore_sandbox_from(root, s_dir, last_acc)
            rollback_action = "AUTO_RESTORED (checkpoint:_last_accepted)"
        else:
            _restore_sandbox_from(root, s_dir, root)
            rollback_action = "AUTO_RESTORED (ROOT)"

    record = {
        "id": tid,
        "category": category,
        "verdict": verdict,
        "reason": reason,
        "gate1_pass": True,
        "gate2_pass": gate2_pass,
        "baseline": base_data,
        "remediation": rem_outcome.to_dict(),
        "suite_status": suite_detail,
        "rollback_action": rollback_action,
        "redactions": total_red,
    }
    (s_dir / "logs" / f"{tid}_verify.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    hist_path = s_dir / "logs" / f"{tid}_attempt_history.json"
    hist: List[Dict[str, Any]] = []
    if hist_path.is_file():
        try:
            hist = json.loads(hist_path.read_text(encoding="utf-8"))
        except Exception:
            hist = []
    hist.append(
        {
            "attempt": len(hist) + 1,
            "id": tid,
            "category": category,
            "verdict": verdict,
            "reason": reason,
            "control_status": rem_outcome.control_status,
            "breach_status": rem_outcome.breach_status,
            "suite_status": suite_detail,
            "rollback_action": rollback_action,
        }
    )
    hist_path.write_text(json.dumps(hist, indent=2, ensure_ascii=False), encoding="utf-8")

    g2_str = "PASS" if gate2_pass else "FAIL"
    lines = [
        f"[VERIFY] id={tid} category={category} verdict={verdict}",
        f"Gate 1 (Invariant Breach): PASS (control={base_data['control_status']}, breach={base_data['breach_status']})",
        f"Gate 2 (Remediation): {g2_str} (control={rem_outcome.control_status}, breach={rem_outcome.breach_status}, suite={suite_detail})",
        f"Security Hygiene: redactions={total_red} masked | unredacted={len(unredacted)} | rollback={rollback_action}",
        f"Reason: {reason}",
    ]
    print("\n".join(lines))
    return 0 if gate2_pass else 1


# ---------------------------------------------------------------------------
# Subcommand: sandbox (fix, save, rollback, diff, clean)
# ---------------------------------------------------------------------------


def _collect_source_files_for_diff(base: Path, global_excl: set[str], root_excl: set[str]) -> Dict[str, Path]:
    files: Dict[str, Path] = {}
    if not base.is_dir():
        return files
    base_res = base.resolve()
    for dirpath, dirnames, filenames in os.walk(base_res):
        dp = Path(dirpath)
        rel_dir = dp.relative_to(base_res)
        at_root = rel_dir == Path(".")
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in global_excl and not (at_root and d in root_excl)
        )
        for fname in sorted(filenames):
            fp = dp / fname
            if fp.suffix.lower() in BINARY_EXTS or fname.lower().endswith((".pyc", ".pyo", ".class")):
                continue
            rel = fname if at_root else f"{rel_dir.as_posix()}/{fname}"
            files[rel] = fp
    return files


def _read_text_lines_for_diff(fp: Path) -> Optional[List[str]]:
    try:
        if fp.stat().st_size > 2_000_000:
            return None
        raw = fp.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace").splitlines()


def cmd_sandbox(args: argparse.Namespace) -> int:
    root, s_dir, _, cache_dir = resolve_session(args.s, args.root)
    global_excl, root_excl = _compute_sandbox_exclusions(root, args.exclude or [])

    if args.mode in ("create", "fix"):
        dir_name = "sandbox" if args.mode == "create" else "sandbox-fix"
        target = s_dir / dir_name
        if target.exists():
            if not args.force:
                raise SystemExit(f"[vs.py] ERROR: {target} already exists (pass --force to overwrite)")
            _remove_readonly_and_rmtree(target)
        t0 = time.monotonic()
        copied = _copy_project_tree(root, target, global_excl, root_excl)
        dur = time.monotonic() - t0
        print(f"[vs sandbox {args.mode}] path={rel_posix(target, root)} files={copied} duration={dur:.2f}s")
        return 0

    if args.mode == "save":
        if not args.id:
            raise SystemExit("[vs.py] ERROR: --id is required for sandbox --mode save")
        dest, copied = _save_sandbox_checkpoint(root, s_dir, args.id)
        print(f"[vs sandbox save] id={sanitize_id(args.id)} path={rel_posix(dest, root)} files={copied}")
        return 0

    if args.mode == "rollback":
        if not args.id:
            raise SystemExit("[vs.py] ERROR: --id is required for sandbox --mode rollback")
        ckpt = _checkpoint_dir(s_dir, args.id)
        if ckpt.is_dir():
            src_dir, src_lbl = ckpt, rel_posix(ckpt, root)
        else:
            src_dir, src_lbl = root, "ROOT"
        copied = _restore_sandbox_from(root, s_dir, src_dir)
        print(f"[vs sandbox rollback] id={sanitize_id(args.id)} restored_from={src_lbl} files={copied}")
        return 0

    if args.mode == "diff":
        fix_dir = s_dir / "sandbox-fix"
        if not fix_dir.is_dir():
            raise SystemExit(f"[vs.py] ERROR: {fix_dir} not found; run --mode fix first")
        sb_dir = s_dir / "sandbox"
        base_dir = sb_dir if sb_dir.is_dir() else root
        base_map = _collect_source_files_for_diff(base_dir, global_excl, root_excl)
        fix_map = _collect_source_files_for_diff(fix_dir, global_excl, root_excl)

        file_diffs: List[Tuple[str, str]] = []
        for rel in sorted(set(base_map) | set(fix_map)):
            b_fp, f_fp = base_map.get(rel), fix_map.get(rel)
            a_lines = _read_text_lines_for_diff(b_fp) if b_fp is not None else []
            b_lines = _read_text_lines_for_diff(f_fp) if f_fp is not None else []
            if a_lines is None or b_lines is None or a_lines == b_lines:
                continue
            udiff = list(difflib.unified_diff(a_lines, b_lines, fromfile=f"a/{rel}", tofile=f"b/{rel}", n=2, lineterm=""))
            if udiff:
                file_diffs.append((rel, "\n".join(udiff)))

        full_diff_text, red_cnt = redact_secrets("\n\n".join(d for _, d in file_diffs))
        diff_file = s_dir / "logs" / "sandbox-fix.diff"
        diff_file.write_text(full_diff_text + ("\n" if full_diff_text else ""), encoding="utf-8")

        header = (
            f"[vs sandbox diff] files_changed={len(file_diffs)} redactions={red_cnt} "
            f"saved={rel_posix(diff_file, root)}"
        )
        if not file_diffs:
            print(f"{header} (no changes)")
            return 0

        max_out = 7900
        out = header + "\n" + full_diff_text
        if len(out) > max_out:
            note = f"\n... (truncated to <=8000 chars; full diff in {rel_posix(diff_file, root)})"
            out = out[: max_out - len(note)] + note
        print(out)
        return 0

    # mode == "clean"
    cleaned: List[str] = []
    for label, target in (
        ("sandbox", s_dir / "sandbox"),
        ("sandbox-fix", s_dir / "sandbox-fix"),
        ("tmp", s_dir / "tmp"),
        (".cache", cache_dir),
    ):
        if target.exists():
            _remove_readonly_and_rmtree(target)
            cleaned.append(label)

    before_file = s_dir / "logs" / "fs-before.txt"
    mode_file = s_dir / "logs" / ".snapshot-mode"
    snap_mode = mode_file.read_text(encoding="utf-8").strip() if mode_file.is_file() else None
    before_lines = before_file.read_text(encoding="utf-8", errors="replace").splitlines() if before_file.is_file() else []

    actual_mode, after_lines = take_snapshot(root, forced_mode=snap_mode)
    diff = diff_snapshots(before_lines, after_lines, actual_mode)
    removed_caches = _clean_new_agent_caches(root, diff, actual_mode)
    if removed_caches:
        actual_mode, after_lines = take_snapshot(root, forced_mode=actual_mode)
        diff = diff_snapshots(before_lines, after_lines, actual_mode)

    after_file = s_dir / "logs" / "fs-after.txt"
    after_file.write_text(("\n".join(after_lines) + "\n") if after_lines else "", encoding="utf-8")

    dirty_items = [
        f"{k}: {it}"
        for k, items in diff.items()
        if k not in ("resolved", "removed")
        for it in items
    ]
    lines = [
        f"[vs sandbox clean] removed_dirs=[{', '.join(cleaned) or 'none'}] "
        f"auto_removed_caches=[{', '.join(removed_caches) or 'none'}]",
    ]
    if not dirty_items:
        lines.append("cleanliness: CLEAN (0 new/modified files outside .bughunt/)")
    else:
        lines.append(f"cleanliness: DIRTY ({len(dirty_items)} changes outside .bughunt/):")
        for item in dirty_items[:8]:
            lines.append(f"  - {trunc(item, 140)}")
    print("\n".join(lines))
    return 0


# ---------------------------------------------------------------------------
# Subcommand: summary
# ---------------------------------------------------------------------------


def _extract_redacted_snippet(log_path: Path, max_lines: int = 5) -> str:
    if not log_path.is_file():
        return ""
    raw = log_path.read_text(encoding="utf-8", errors="replace")
    clean, _ = redact_secrets(strip_ansi(raw))
    lines = [ln.rstrip() for ln in clean.splitlines() if ln.strip()]
    interesting: List[str] = []
    for ln in lines:
        if any(
            k in ln
            for k in (
                POC_PREFIX,
                "AssertionError",
                "FAIL:",
                "FAILED",
                "VERISEC_NET_GUARD",
                "PermissionError",
                "exit=",
            )
        ):
            if ln.strip().startswith(POC_PREFIX):
                try:
                    rec = json.loads(ln.strip()[len(POC_PREFIX) :].strip())
                    interesting.append(
                        f"{POC_PREFIX} id={rec.get('id')} breach={rec.get('breach_detected')} "
                        f"ctrl={rec.get('control_authorized')} | {trunc(str(rec.get('details', '')), 180)}"
                    )
                    continue
                except json.JSONDecodeError:
                    pass
            interesting.append(trunc(ln, 200))
    if not interesting:
        interesting = [trunc(ln, 150) for ln in lines[-max_lines:]]
    return "\n".join(interesting[:max_lines])


def cmd_summary(args: argparse.Namespace) -> int:
    root, s_dir, _, _ = resolve_session(args.s, args.root)
    logs_dir = s_dir / "logs"
    if not logs_dir.is_dir():
        raise SystemExit(f"[vs.py] ERROR: logs directory missing: {logs_dir}")

    surf_file = logs_dir / "surface_map.json"
    surface_count = 0
    flagged_count = 0
    if surf_file.is_file():
        sdata = json.loads(surf_file.read_text(encoding="utf-8"))
        surface_count = int(sdata.get("surface_count", 0))
        flagged_count = int(sdata.get("flagged_count", 0))

    verify_files = sorted(logs_dir.glob("*_verify.json"))
    confirmed: List[Dict[str, Any]] = []
    refuted: List[Dict[str, Any]] = []
    other: List[Dict[str, Any]] = []
    total_redactions = 0
    for vf in verify_files:
        d = json.loads(vf.read_text(encoding="utf-8"))
        total_redactions += int(d.get("redactions", 0))
        v = d.get("verdict")
        if v == "CONFIRMED_REMEDIATED":
            confirmed.append(d)
        elif v == "REFUTED_SAFE":
            refuted.append(d)
        else:
            other.append(d)

    rejected_attempts: List[Dict[str, Any]] = []
    for hf in sorted(logs_dir.glob("*_attempt_history.json")):
        for att in json.loads(hf.read_text(encoding="utf-8")):
            if str(att.get("verdict", "")).startswith("REJECTED_"):
                rejected_attempts.append(att)

    out: List[str] = [
        f"### VeriSec Security Summary (`{s_dir.name}`)",
        f"- **Surface Endpoints:** {surface_count} (Flagged: {flagged_count}) | "
        f"**Confirmed & Remediated:** {len(confirmed)} | **Refuted Safe:** {len(refuted)} | "
        f"**Auto-Rolled-Back Patch Attempts:** {len(rejected_attempts)} | **Secrets Masked:** {total_redactions}",
        "",
    ]

    if confirmed:
        out.append("#### Confirmed & Remediated Vulnerabilities (Dual-Gate Verified)")
        out.append("| ID | Category | Gate 1 (Baseline) | Gate 2 (Sandbox-Fix) | Suite | Redactions | Verdict |")
        out.append("|---|---|---|---|---|---:|---|")
        for d in confirmed:
            b = d["baseline"]
            r = d["remediation"]
            out.append(
                f"| {d['id']} | {d['category']} | Ctrl={b['control_status']}, {b['breach_status']} | "
                f"Ctrl={r['control_status']}, {r['breach_status']} | {d['suite_status']} | {d['redactions']} | {d['verdict']} |"
            )
        out.append("")

    if refuted or rejected_attempts or other:
        out.append("#### Refuted Hypotheses & Rejected Patch Rollbacks")
        out.append("| ID | Category | Outcome | Control | Breach Status | Action / Reason |")
        out.append("|---|---|---|---|---|---|")
        for d in refuted + other:
            b = d["baseline"]
            out.append(
                f"| {d['id']} | {d['category']} | {d['verdict']} | {b['control_status']} | {b['breach_status']} | {d['reason']} |"
            )
        for att in rejected_attempts:
            out.append(
                f"| {att['id']} (Try #{att['attempt']}) | {att['category']} | {att['verdict']} | "
                f"{att['control_status']} | {att['breach_status']} | {att['rollback_action']} — {att['reason']} |"
            )
        out.append("")

    if args.snippets:
        for d in confirmed + refuted:
            b = d["baseline"]
            base_log = root / b["log_path"] if b.get("log_path") else (logs_dir / f"{d['id']}_baseline.log")
            snip = _extract_redacted_snippet(base_log, max_lines=4)
            if snip:
                out.append(f"**Redacted Snippet `{d['id']}` (Baseline):**")
                out.append("```text")
                out.append(snip)
                out.append("```")

    summary_text, _ = redact_secrets("\n".join(out))
    print(summary_text)
    return 0


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vs.py",
        description="VeriSec v1.0 CLI: API surface-map, 100% network-isolated PoCs, secret redaction & Dual-Gate verify.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="Initialize .bughunt/sec-<ts>/ session, netguard & fs-before.txt")
    p_init.add_argument("--root", default=None, help="Project ROOT directory")
    p_init.set_defaults(func=cmd_init)

    p_surf = sub.add_parser("surface-map", help="Scan API endpoints, auth guards, inputs & 4 logic-flaw categories")
    p_surf.add_argument("--root", default=None, help="Project ROOT directory")
    p_surf.add_argument("--scope", default=None, help="Optional relative subpath to scope scan")
    p_surf.add_argument("--s", default=None, help="Optional session directory to store surface_map.json")
    p_surf.add_argument("--max-lines", type=int, default=35, help="Max output lines (<=35)")
    p_surf.add_argument("--json", action="store_true", help="Emit single-line JSON output")
    p_surf.set_defaults(func=cmd_surface_map)

    p_poc = sub.add_parser("isolated-poc", help="Run PoC/test command in 100%% outbound network-isolated mode with secret redaction")
    p_poc.add_argument("--s", required=True, help="Session directory path")
    p_poc.add_argument("--id", required=True, help="Target finding ID (e.g. sec1)")
    p_poc.add_argument("--phase", required=True, choices=("baseline", "remediation"), help="Execution phase")
    p_poc.add_argument("--category", default="IDOR_BOLA", help="Vulnerability category tag")
    p_poc.add_argument("--cwd", default=None, help="Working directory override")
    p_poc.add_argument("--root", default=None, help="Project ROOT override")
    p_poc.add_argument("--timeout", type=int, default=60, help="Timeout seconds")
    p_poc.add_argument("cmd", nargs=argparse.REMAINDER, help="PoC command after --")
    p_poc.set_defaults(func=cmd_isolated_poc)

    p_red = sub.add_parser("redact-output", help="Redact secrets/tokens/passwords from text, file, stdin, or session logs")
    p_red.add_argument("--text", default=None, help="Inline text to redact")
    p_red.add_argument("--input-file", default=None, help="Input file path")
    p_red.add_argument("--output-file", default=None, help="Output file path")
    p_red.add_argument("--s", default=None, help="Session directory for --scan")
    p_red.add_argument("--root", default=None, help="Project ROOT override")
    p_red.add_argument("--scan", action="store_true", help="Scan & scrub all logs/reports inside session S")
    p_red.set_defaults(func=cmd_redact_output)

    p_ver = sub.add_parser("verify", help="Enforce Gate 1 (Invariant Breach) & Gate 2 (Remediation + Non-Regression + Auto-Rollback)")
    p_ver.add_argument("--s", required=True, help="Session directory path")
    p_ver.add_argument("--id", required=True, help="Target finding ID")
    p_ver.add_argument("--category", default="IDOR_BOLA", help="Fallback category")
    p_ver.add_argument("--gate1-only", action="store_true", help="Evaluate Gate 1 baseline breach only")
    p_ver.add_argument("--auto-rollback", action="store_true", help="Auto-restore S/sandbox-fix checkpoint on Gate 2 REJECTED")
    p_ver.add_argument("--poc-cmd", default=None, help="Override PoC command string for remediation")
    p_ver.add_argument("--test-cmd", default=None, help="Existing project test command string for Gate 2 regression check")
    p_ver.add_argument("--cwd", default=None, help="Working directory override")
    p_ver.add_argument("--timeout", type=int, default=120, help="Timeout seconds")
    p_ver.add_argument("--root", default=None, help="Project ROOT override")
    p_ver.set_defaults(func=cmd_verify)

    p_sb = sub.add_parser("sandbox", help="Manage S/sandbox-fix, checkpoints, redacted diff, and cleanliness check")
    p_sb.add_argument("--s", required=True, help="Session directory path")
    p_sb.add_argument("--mode", required=True, choices=("create", "fix", "save", "rollback", "diff", "clean"), help="Sandbox action")
    p_sb.add_argument("--id", default=None, help="Checkpoint ID for save/rollback")
    p_sb.add_argument("--exclude", action="append", default=[], help="Extra dir names to exclude")
    p_sb.add_argument("--force", action="store_true", help="Overwrite existing sandbox directory")
    p_sb.add_argument("--root", default=None, help="Project ROOT override")
    p_sb.set_defaults(func=cmd_sandbox)

    p_log = sub.add_parser("log", help="Update worklog.md line-1 Status and append redacted 1-line entries")
    p_log.add_argument("--s", required=True, help="Session directory path")
    p_log.add_argument("--status", default=None, help="New Status line text")
    p_log.add_argument("--entry", action="append", default=None, help="Entry text (repeatable)")
    p_log.add_argument("--entry-file", default=None, help="Optional file of entries")
    p_log.add_argument("--root", default=None, help="Project ROOT override")
    p_log.set_defaults(func=cmd_log)

    p_sum = sub.add_parser("summary", help="Emit redacted Markdown tables & snippets from session JSONs")
    p_sum.add_argument("--s", required=True, help="Session directory path")
    p_sum.add_argument("--snippets", action="store_true", help="Include compact redacted PoC log snippets")
    p_sum.add_argument("--root", default=None, help="Project ROOT override")
    p_sum.set_defaults(func=cmd_summary)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
