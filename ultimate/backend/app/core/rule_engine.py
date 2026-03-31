"""Layer 0/1 Rule Engine — migrated from 4SSH_CONTROL core with async interface.

Layer 0: Hard blacklist, sensitive paths, whitelist.
Layer 1: Contextual escalation rules, command chaining detection.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


# ═══ Regex patterns ══════════════════════════════════════════

_CHAIN_SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\||`|\$\()\s*")
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07")
_ANSI_C_QUOTE_RE = re.compile(r"\$'([^']*)'")
_MULTI_SPACE_RE = re.compile(r"  +")
_MULTI_SLASH_RE = re.compile(r"/{2,}")
_DOT_SLASH_RE = re.compile(r"/\./")
_DOTDOT_RE = re.compile(r"/[^/]+/\.\./")
_ROOT_DOTDOT_RE = re.compile(r"/\.\./")

_SUDO_RE = re.compile(r"^sudo\s+(?:(?:-u\s+\S+|-[A-Za-z]+|--\S+)\s+)*")
_PREFIX_WRAPPERS = re.compile(
    r"^(?:doas\s+|busybox\s+|"
    r"env(?:\s+(?:-\S+|\S+=\S+))*\s+|"
    r"nice\s+|ionice\s+|timeout\s+\S+\s+|command\s+|exec\s+|"
    r"strace\s+(?:-\S+\s+)*|ltrace\s+(?:-\S+\s+)*|"
    r"su\s+-c\s+['\"]?|"
    r"bash\s+-c\s+['\"]?|sh\s+-c\s+['\"]?|"
    r"eval\s+['\"]?|"
    r"chroot\s+\S+\s+)"
)

_UNICODE_CONFUSABLES = str.maketrans({
    "\u2212": "-", "\u2013": "-", "\u2014": "-", "\uff0d": "-",
    "\u2010": "-", "\u2011": "-", "\uff1b": ";", "\uff5c": "|",
    "\uff06": "&", "\u2018": "'", "\u2019": "'", "\u201c": '"',
    "\u201d": '"', "\uff0f": "/", "\u2215": "/", "\uff3e": "^",
})

_RM_LONG_FLAGS = {
    "--recursive": "-r", "--force": "-f", "--no-preserve-root": "", "--verbose": "-v",
}


# ═══ Normalization helpers ═══════════════════════════════════

def _normalize_paths(cmd: str) -> str:
    cmd = _MULTI_SLASH_RE.sub("/", cmd)
    prev = None
    while cmd != prev:
        prev = cmd
        cmd = _DOT_SLASH_RE.sub("/", cmd)
    prev = None
    while cmd != prev:
        prev = cmd
        cmd = _DOTDOT_RE.sub("/", cmd)
    return _ROOT_DOTDOT_RE.sub("/", cmd)


def _decode_ansi_c(inner: str) -> str:
    try:
        return inner.encode("utf-8").decode("unicode_escape")
    except Exception:
        return inner


def _normalize_command_name(cmd: str) -> str:
    if not cmd:
        return cmd
    i, name_chars = 0, []
    while i < len(cmd) and cmd[i] not in (" ", "\t"):
        ch = cmd[i]
        if ch == "\\" and i + 1 < len(cmd):
            name_chars.append(cmd[i + 1])
            i += 2
        elif ch in ("'", '"'):
            i += 1
        else:
            name_chars.append(ch)
            i += 1
    return "".join(name_chars) + cmd[i:]


def _normalize_rm_flags(cmd: str) -> str:
    parts = cmd.split()
    if not parts:
        return cmd
    base = parts[0].rsplit("/", 1)[-1]
    if base != "rm":
        return cmd
    flags, args = [], []
    for p in parts[1:]:
        if p.startswith("--"):
            repl = _RM_LONG_FLAGS.get(p, p)
            if repl:
                flags.append(repl)
        elif p.startswith("-") and not p[1:].lstrip("-").isdigit():
            flags.append(p)
        else:
            args.append(p)
    merged = set()
    for f in flags:
        for ch in f.lstrip("-"):
            merged.add(ch)
    canonical = ""
    for ch in "rf":
        if ch in merged:
            canonical += ch
            merged.discard(ch)
    canonical += "".join(sorted(merged))
    flag_str = "-" + canonical if canonical else ""
    return " ".join(filter(None, [parts[0], flag_str] + args))


def _unwrap_prefix_commands(cmd: str) -> str:
    original = cmd
    prev = None
    unwrapped = cmd
    while unwrapped != prev:
        prev = unwrapped
        m = _SUDO_RE.match(unwrapped)
        if m:
            unwrapped = unwrapped[m.end():].strip().lstrip("'\"")
            continue
        unwrapped = _PREFIX_WRAPPERS.sub("", unwrapped).strip().lstrip("'\"")
    if unwrapped and unwrapped != original:
        return original + "\n" + unwrapped
    return original


def _normalize_shell(cmd: str) -> str:
    cmd = cmd.translate(_UNICODE_CONFUSABLES)
    cmd = _ANSI_C_QUOTE_RE.sub(lambda m: _decode_ansi_c(m.group(1)), cmd)
    cmd = _MULTI_SPACE_RE.sub(" ", cmd).strip()
    cmd = _normalize_paths(cmd)
    cmd = _normalize_command_name(cmd)
    cmd = _unwrap_prefix_commands(cmd)
    cmd = _normalize_rm_flags(cmd)
    return cmd


def sanitize(raw: str) -> str:
    cleaned = _ANSI_ESCAPE_RE.sub("", raw)
    cleaned = "".join(ch if (ch >= " " or ch in "\t\n\r") else " " for ch in cleaned)
    cleaned = cleaned.strip()
    return _normalize_shell(cleaned)


# ═══ Rule dataclasses ════════════════════════════════════════

@dataclass
class RuleMatch:
    verdict: str      # allow | deny | escalate
    confidence: float
    category: str
    reason: str
    severity: str
    agent: str = "rule_engine"
    elapsed_ms: float = 0.0


@dataclass
class RuleSet:
    whitelist: list[str] = field(default_factory=list)
    blacklist: list[tuple[re.Pattern, str, str]] = field(default_factory=list)     # (pattern, reason, severity)
    sensitive_paths: list[tuple[str, str, str, str]] = field(default_factory=list)  # (path, reason, severity, action)
    escalation_rules: list[tuple[re.Pattern, str, str, str]] = field(default_factory=list)  # (pattern, reason, severity, action)
    dangerous_content: list[tuple[str, str, str]] = field(default_factory=list)    # (pattern, reason, severity)


_BINARY_SUSPICIOUS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"/bin/sh\b"), "Вызов /bin/sh в бинарнике", "high"),
    (re.compile(r"/bin/bash\b"), "Вызов /bin/bash в бинарнике", "high"),
    (re.compile(r"\bexecve\b"), "execve syscall", "medium"),
    (re.compile(r"\bsystem\b"), "system() — произвольные команды", "high"),
    (re.compile(r"\bsocket\b.*\bconnect\b", re.DOTALL), "Сетевое подключение", "high"),
    (re.compile(r"/dev/tcp/"), "Reverse shell /dev/tcp", "critical"),
    (re.compile(r"\bpopen\b"), "popen() — shell exec", "high"),
    (re.compile(r"\bptrace\b"), "ptrace — process injection", "high"),
    (re.compile(r"/etc/shadow"), "Обращение к /etc/shadow", "critical"),
    (re.compile(r"\bkeylog"), "Потенциальный кейлоггер", "critical"),
]


# ═══ Rule Engine ═════════════════════════════════════════════

class RuleEngine:
    """Synchronous Layer-0/1 rule engine. Called from async context via run_in_executor."""

    def __init__(self, rules: RuleSet) -> None:
        self._whitelist = {cmd.strip().lower() for cmd in rules.whitelist}
        self._blacklist = rules.blacklist
        self._sensitive_paths = rules.sensitive_paths
        self._escalation_rules = rules.escalation_rules
        self._dangerous_content = rules.dangerous_content

    def evaluate(self, command: str) -> RuleMatch | None:
        t0 = time.perf_counter()
        cmd = sanitize(command)
        if not cmd or cmd.startswith("#"):
            return None

        variants = cmd.split("\n")
        primary = variants[0]
        normalized = primary.lower()

        for variant in variants:
            for pattern, reason, severity in self._blacklist:
                if pattern.search(variant):
                    return RuleMatch("deny", 1.0, "destructive", reason, severity,
                                     elapsed_ms=(time.perf_counter() - t0) * 1000)

        for variant in variants:
            for path_pat, reason, severity, action in self._sensitive_paths:
                if path_pat in variant:
                    return RuleMatch(action, 1.0, "risky", f"Чувствительный файл: {reason} ({path_pat})",
                                     severity, elapsed_ms=(time.perf_counter() - t0) * 1000)

        for variant in variants:
            for pattern, reason, severity, action in self._escalation_rules:
                if pattern.search(variant):
                    return RuleMatch(action, 1.0, "risky", f"Контекстное правило: {reason}",
                                     severity, elapsed_ms=(time.perf_counter() - t0) * 1000)

        sub_commands = _CHAIN_SPLIT_RE.split(primary)
        if len(sub_commands) > 1:
            for sub in sub_commands:
                sub = sub.strip().rstrip(")")
                if not sub:
                    continue
                sub_result = self._evaluate_single(sub)
                if sub_result and sub_result.verdict == "deny":
                    sub_result.reason = f"[в цепочке] {sub_result.reason}"
                    return sub_result
            return None

        if normalized in self._whitelist:
            return RuleMatch("allow", 1.0, "safe", f"Команда '{primary}' в белом списке",
                             "low", elapsed_ms=(time.perf_counter() - t0) * 1000)

        base_cmd = normalized.split()[0] if normalized else ""
        if base_cmd in self._whitelist:
            return RuleMatch("allow", 0.9, "safe", f"Базовая команда '{base_cmd}' в белом списке",
                             "low", elapsed_ms=(time.perf_counter() - t0) * 1000)

        return None

    def _evaluate_single(self, command: str) -> RuleMatch | None:
        stripped = _normalize_shell(command.strip())
        variants = stripped.split("\n")
        for variant in variants:
            for pattern, reason, severity in self._blacklist:
                if pattern.search(variant):
                    return RuleMatch("deny", 1.0, "destructive", reason, severity)
        return None

    def scan_content(self, text: str) -> RuleMatch | None:
        for pattern, reason, severity in self._dangerous_content:
            if pattern in text:
                return RuleMatch("deny", 0.95, "destructive", f"Опасное содержимое: {reason}", severity,
                                 agent="content_monitor")
        return None

    def scan_strings(self, strings_output: str) -> RuleMatch | None:
        for pattern, reason, severity in _BINARY_SUSPICIOUS:
            if pattern.search(strings_output):
                verdict = "deny" if severity in ("critical", "high") else "escalate"
                return RuleMatch(verdict, 0.9, "risky", f"Подозрительный бинарник: {reason}", severity,
                                 agent="binary_inspector")
        return None


# ═══ Network Rule Engine ═════════════════════════════════════

@dataclass
class NetworkRuleSet:
    vendor: str = "generic_network"
    safe_commands: list[str] = field(default_factory=list)
    dangerous_patterns: list[tuple[re.Pattern, str, str]] = field(default_factory=list)
    critical_patterns: list[tuple[re.Pattern, str, str]] = field(default_factory=list)
    escalation_patterns: list[tuple[re.Pattern, str, str, str]] = field(default_factory=list)


class NetworkRuleEngine:
    def __init__(self, rules: NetworkRuleSet) -> None:
        self._vendor = rules.vendor
        self._safe = {cmd.strip().lower() for cmd in rules.safe_commands}
        self._dangerous = rules.dangerous_patterns
        self._critical = rules.critical_patterns
        self._escalation = rules.escalation_patterns

    def evaluate(self, command: str) -> RuleMatch | None:
        t0 = time.perf_counter()
        cmd = "".join(ch if (ch >= " " or ch in "\t\n\r") else "" for ch in command).strip()
        if not cmd:
            return None

        normalized = cmd.lower().strip()
        base = normalized.split()[0] if normalized else ""
        if normalized in self._safe or base in self._safe:
            conf = 1.0 if normalized in self._safe else 0.9
            return RuleMatch("allow", conf, "safe", f"[{self._vendor}] Безопасная команда", "low",
                             agent="network_rule_engine", elapsed_ms=(time.perf_counter() - t0) * 1000)

        for pattern, reason, severity in self._critical:
            if pattern.search(cmd):
                return RuleMatch("deny", 1.0, "destructive", f"[{self._vendor}] КРИТИЧНАЯ: {reason}", severity,
                                 agent="network_rule_engine", elapsed_ms=(time.perf_counter() - t0) * 1000)

        for pattern, reason, severity in self._dangerous:
            v = "deny" if severity == "critical" else "escalate"
            if pattern.search(cmd):
                return RuleMatch(v, 1.0, "risky", f"[{self._vendor}] Опасная: {reason}", severity,
                                 agent="network_rule_engine", elapsed_ms=(time.perf_counter() - t0) * 1000)

        for pattern, reason, severity, action in self._escalation:
            if pattern.search(cmd):
                return RuleMatch(action, 1.0, "risky", f"[{self._vendor}] Контекстное: {reason}", severity,
                                 agent="network_rule_engine", elapsed_ms=(time.perf_counter() - t0) * 1000)

        return None
