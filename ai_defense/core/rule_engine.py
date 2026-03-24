from __future__ import annotations

import re
import time

from .config import RulesConfig
from .models import (
    AgentDecision,
    CommandCategory,
    Severity,
    Verdict,
)


_CHAIN_SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\||`|\$\()\s*")

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07")


_ANSI_C_QUOTE_RE = re.compile(r"\$'([^']*)'")
_MULTI_SPACE_RE = re.compile(r"  +")

_RM_LONG_FLAGS = {
    "--recursive": "-r",
    "--force": "-f",
    "--no-preserve-root": "",
    "--verbose": "-v",
}


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
    "\u2212": "-",   # MINUS SIGN → HYPHEN-MINUS
    "\u2013": "-",   # EN DASH
    "\u2014": "-",   # EM DASH
    "\uff0d": "-",   # FULLWIDTH HYPHEN-MINUS
    "\u2010": "-",   # HYPHEN
    "\u2011": "-",   # NON-BREAKING HYPHEN
    "\uff1b": ";",   # FULLWIDTH SEMICOLON
    "\uff5c": "|",   # FULLWIDTH VERTICAL LINE
    "\uff06": "&",   # FULLWIDTH AMPERSAND
    "\u2018": "'",   # LEFT SINGLE QUOTATION
    "\u2019": "'",   # RIGHT SINGLE QUOTATION
    "\u201c": '"',   # LEFT DOUBLE QUOTATION
    "\u201d": '"',   # RIGHT DOUBLE QUOTATION
    "\uff0f": "/",   # FULLWIDTH SOLIDUS
    "\u2215": "/",   # DIVISION SLASH
    "\uff3e": "^",   # FULLWIDTH CIRCUMFLEX
})


_MULTI_SLASH_RE = re.compile(r"/{2,}")
_DOT_SLASH_RE = re.compile(r"/\./")
_DOTDOT_RE = re.compile(r"/[^/]+/\.\./")
_ROOT_DOTDOT_RE = re.compile(r"/\.\./")


def _normalize_paths(cmd: str) -> str:
    """Collapse ///etc///shadow → /etc/shadow, /etc/./shadow → /etc/shadow, /tmp/../../ → /."""
    cmd = _MULTI_SLASH_RE.sub("/", cmd)
    prev = None
    while cmd != prev:
        prev = cmd
        cmd = _DOT_SLASH_RE.sub("/", cmd)
    prev = None
    while cmd != prev:
        prev = cmd
        cmd = _DOTDOT_RE.sub("/", cmd)
    cmd = _ROOT_DOTDOT_RE.sub("/", cmd)
    return cmd


def _normalize_shell_obfuscation(cmd: str) -> str:
    """Normalize shell obfuscation: unicode, ANSI-C $'...', rm flag variants, command-name quoting."""
    cmd = cmd.translate(_UNICODE_CONFUSABLES)
    cmd = _ANSI_C_QUOTE_RE.sub(lambda m: _decode_ansi_c(m.group(1)), cmd)
    cmd = _MULTI_SPACE_RE.sub(" ", cmd).strip()
    cmd = _normalize_paths(cmd)
    cmd = _normalize_command_name(cmd)
    cmd = _unwrap_prefix_commands(cmd)
    cmd = _normalize_rm_flags(cmd)
    return cmd


def _unwrap_prefix_commands(cmd: str) -> str:
    """Strip known prefix wrappers so the actual command is visible to rules.

    Returns BOTH the original and unwrapped forms joined by a newline
    so regex can match either. The evaluate method splits on newline.
    """
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


def _decode_ansi_c(inner: str) -> str:
    """Decode \\x72\\x6d style ANSI-C content to plain text."""
    try:
        return inner.encode("utf-8").decode("unicode_escape")
    except Exception:
        return inner


def _normalize_command_name(cmd: str) -> str:
    """Strip quotes and backslashes only from the command name (first token)."""
    if not cmd:
        return cmd
    i = 0
    name_chars = []
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
    rest = cmd[i:]
    return "".join(name_chars) + rest


def _normalize_rm_flags(cmd: str) -> str:
    """Normalize rm --recursive --force / → rm -rf / and rm -r -f / → rm -rf /."""
    parts = cmd.split()
    if not parts:
        return cmd
    base = parts[0].rsplit("/", 1)[-1]
    if base != "rm":
        return cmd
    flags = []
    args = []
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


_BINARY_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"/bin/sh\b"), "Вызов /bin/sh в бинарнике", Severity.HIGH),
    (re.compile(r"/bin/bash\b"), "Вызов /bin/bash в бинарнике", Severity.HIGH),
    (re.compile(r"\bexecve\b"), "Использование execve syscall", Severity.MEDIUM),
    (re.compile(r"\bsystem\b"), "Использование system() — выполнение произвольных команд", Severity.HIGH),
    (re.compile(r"\bsocket\b.*\bconnect\b", re.DOTALL), "Сетевое подключение (socket+connect)", Severity.HIGH),
    (re.compile(r"/dev/tcp/"), "Reverse shell через /dev/tcp", Severity.CRITICAL),
    (re.compile(r"\bpopen\b"), "Использование popen() — выполнение команд через shell", Severity.HIGH),
    (re.compile(r"\bdlopen\b"), "Динамическая загрузка библиотек (dlopen)", Severity.MEDIUM),
    (re.compile(r"\bptrace\b"), "Использование ptrace — отладка/инъекция процессов", Severity.HIGH),
    (re.compile(r"/etc/shadow"), "Обращение к /etc/shadow", Severity.CRITICAL),
    (re.compile(r"/etc/passwd"), "Обращение к /etc/passwd", Severity.HIGH),
    (re.compile(r"\bkeylog"), "Потенциальный кейлоггер", Severity.CRITICAL),
    (re.compile(r"\bcrypt\b"), "Криптографические операции", Severity.MEDIUM),
    (re.compile(r"\bBASE64\b|base64_", re.IGNORECASE), "Base64 обфускация", Severity.MEDIUM),
]


class RuleEngine:
    """Layer-0 instant filter: whitelist/blacklist/sensitive paths."""

    def __init__(self, rules: RulesConfig) -> None:
        self._whitelist: set[str] = set()
        for cmd in rules.whitelist:
            self._whitelist.add(cmd.strip().lower())

        self._blacklist: list[tuple[re.Pattern, str, Severity]] = []
        for bl in rules.blacklist:
            sev = Severity.HIGH
            try:
                sev = Severity(bl.severity)
            except ValueError:
                pass
            self._blacklist.append((re.compile(bl.pattern), bl.reason, sev))

        self._sensitive_paths: list[tuple[str, str, Severity, Verdict]] = []
        for sp in rules.sensitive_paths:
            sev = Severity.HIGH
            try:
                sev = Severity(sp.severity)
            except ValueError:
                pass
            action = Verdict.DENY if sp.action == "deny" else Verdict.ESCALATE
            self._sensitive_paths.append((sp.pattern, sp.reason, sev, action))

        self._dangerous_content: list[tuple[str, str, Severity]] = []
        for dc in rules.dangerous_content:
            sev = Severity.HIGH
            try:
                sev = Severity(dc.severity)
            except ValueError:
                pass
            self._dangerous_content.append((dc.pattern, dc.reason, sev))

        self._escalation_rules: list[tuple[re.Pattern, str, Severity, Verdict]] = []
        for er in rules.escalation_rules:
            sev = Severity.HIGH
            try:
                sev = Severity(er.severity)
            except ValueError:
                pass
            action = Verdict.DENY if er.action == "deny" else Verdict.ESCALATE
            self._escalation_rules.append((re.compile(er.pattern, re.IGNORECASE), er.reason, sev, action))

    @staticmethod
    def sanitize(raw: str) -> str:
        """Strip ANSI escapes, control characters, and shell obfuscation from input."""
        cleaned = _ANSI_ESCAPE_RE.sub("", raw)
        cleaned = "".join(ch if (ch >= " " or ch in "\t\n\r") else " " for ch in cleaned)
        cleaned = cleaned.strip()
        cleaned = _normalize_shell_obfuscation(cleaned)
        return cleaned

    def evaluate(self, command: str) -> AgentDecision | None:
        """Return an instant decision if the rule matches, else None (pass to agents)."""
        t0 = time.perf_counter()
        sanitized = self.sanitize(command)
        if not sanitized or sanitized.startswith("#"):
            return None

        variants = sanitized.split("\n")
        primary = variants[0]
        normalized = primary.lower()

        for variant in variants:
            for pattern, reason, severity in self._blacklist:
                if pattern.search(variant):
                    return AgentDecision(
                        agent_name="rule_engine",
                        verdict=Verdict.DENY,
                        confidence=1.0,
                        category=CommandCategory.DESTRUCTIVE,
                        reason=reason,
                        severity=severity,
                        elapsed_ms=(time.perf_counter() - t0) * 1000,
                    )

        for variant in variants:
            sp_decision = self.check_sensitive_path(variant)
            if sp_decision is not None:
                sp_decision.elapsed_ms = (time.perf_counter() - t0) * 1000
                return sp_decision

        for variant in variants:
            esc_decision = self._check_escalation_rules(variant)
            if esc_decision is not None:
                esc_decision.elapsed_ms = (time.perf_counter() - t0) * 1000
                return esc_decision

        sub_commands = _CHAIN_SPLIT_RE.split(primary)
        has_chain = len(sub_commands) > 1
        if has_chain:
            for sub in sub_commands:
                sub = sub.strip().rstrip(")")
                if not sub:
                    continue
                sub_result = self._evaluate_single(sub)
                if sub_result and sub_result.verdict == Verdict.DENY:
                    sub_result.reason = f"[в цепочке] {sub_result.reason}"
                    sub_result.elapsed_ms = (time.perf_counter() - t0) * 1000
                    return sub_result
                sp = self.check_sensitive_path(sub)
                if sp and sp.verdict == Verdict.DENY:
                    sp.reason = f"[в цепочке] {sp.reason}"
                    sp.elapsed_ms = (time.perf_counter() - t0) * 1000
                    return sp
                sub_esc = self._check_escalation_rules(sub)
                if sub_esc and sub_esc.verdict == Verdict.DENY:
                    sub_esc.reason = f"[в цепочке] {sub_esc.reason}"
                    sub_esc.elapsed_ms = (time.perf_counter() - t0) * 1000
                    return sub_esc
            return None

        if normalized in self._whitelist:
            return AgentDecision(
                agent_name="rule_engine",
                verdict=Verdict.ALLOW,
                confidence=1.0,
                category=CommandCategory.SAFE,
                reason=f"Команда '{primary}' в белом списке",
                severity=Severity.LOW,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        base_cmd = normalized.split()[0] if normalized else ""
        if base_cmd in self._whitelist:
            return AgentDecision(
                agent_name="rule_engine",
                verdict=Verdict.ALLOW,
                confidence=0.9,
                category=CommandCategory.SAFE,
                reason=f"Базовая команда '{base_cmd}' в белом списке",
                severity=Severity.LOW,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        return None

    def _check_escalation_rules(self, command: str) -> AgentDecision | None:
        """Context-aware rules: catch dangerous *usage patterns*, not commands wholesale."""
        for pattern, reason, severity, action in self._escalation_rules:
            if pattern.search(command):
                return AgentDecision(
                    agent_name="rule_engine",
                    verdict=action,
                    confidence=1.0,
                    category=CommandCategory.RISKY,
                    reason=f"Контекстное правило: {reason}",
                    severity=severity,
                )
        return None

    def _evaluate_single(self, command: str) -> AgentDecision | None:
        """Check a single (non-chained) command against blacklist only.

        Applies sanitization to catch obfuscation within sub-commands.
        """
        stripped = _normalize_shell_obfuscation(command.strip())
        variants = stripped.split("\n")
        for variant in variants:
            for pattern, reason, severity in self._blacklist:
                if pattern.search(variant):
                    return AgentDecision(
                        agent_name="rule_engine",
                        verdict=Verdict.DENY,
                        confidence=1.0,
                        category=CommandCategory.DESTRUCTIVE,
                        reason=reason,
                        severity=severity,
                    )
        return None

    def check_sensitive_path(self, command: str) -> AgentDecision | None:
        """Check if the command targets a sensitive file path."""
        for path_pattern, reason, severity, action in self._sensitive_paths:
            if path_pattern in command:
                return AgentDecision(
                    agent_name="rule_engine",
                    verdict=action,
                    confidence=1.0,
                    category=CommandCategory.RISKY,
                    reason=f"Чувствительный файл: {reason} ({path_pattern})",
                    severity=severity,
                )
        return None

    def scan_content(self, text: str) -> AgentDecision | None:
        """Scan text typed inside interactive programs for dangerous patterns."""
        for pattern, reason, severity in self._dangerous_content:
            if pattern in text:
                return AgentDecision(
                    agent_name="content_monitor",
                    verdict=Verdict.DENY,
                    confidence=0.95,
                    category=CommandCategory.DESTRUCTIVE,
                    reason=f"Опасное содержимое: {reason}",
                    severity=severity,
                )
        return None

    def scan_strings(self, strings_output: str) -> AgentDecision | None:
        """Scan extracted strings from a binary file for suspicious patterns.

        Also checks against dangerous_content rules and blacklist patterns.
        """
        t0 = time.perf_counter()

        for pattern, reason, severity in _BINARY_SUSPICIOUS_PATTERNS:
            if pattern.search(strings_output):
                return AgentDecision(
                    agent_name="binary_inspector",
                    verdict=Verdict.DENY if severity in (Severity.CRITICAL, Severity.HIGH) else Verdict.ESCALATE,
                    confidence=0.9,
                    category=CommandCategory.RISKY,
                    reason=f"Подозрительный бинарник: {reason}",
                    severity=severity,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                )

        for dc_pattern, dc_reason, dc_severity in self._dangerous_content:
            if dc_pattern in strings_output:
                return AgentDecision(
                    agent_name="binary_inspector",
                    verdict=Verdict.DENY,
                    confidence=0.9,
                    category=CommandCategory.DESTRUCTIVE,
                    reason=f"Опасные строки в бинарнике: {dc_reason}",
                    severity=dc_severity,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                )

        return None
