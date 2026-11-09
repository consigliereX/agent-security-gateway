from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Protocol, Sequence, Tuple

from .config import FirewallConfig
from .types import Finding, SecurityContext, Severity

_ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\ufeff")
_SECRET_PLACEHOLDERS = {
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "your_api_key",
    "your_token",
    "redacted",
}

_HOMOGLYPH_MAP = {
    "\u0430": "a",
    "\u0435": "e",
    "\u0456": "i",
    "\u043E": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0391": "a",
    "\u0392": "b",
    "\u0395": "e",
    "\u0399": "i",
    "\u039A": "k",
    "\u039C": "m",
    "\u039D": "n",
    "\u039F": "o",
    "\u03A1": "p",
    "\u03A4": "t",
    "\u03A5": "y",
    "\u03A7": "x",
}


def _fold_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _normalize_text(*parts: str) -> str:
    text = " ".join(part for part in parts if part)
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _fold_homoglyphs(normalized)
    normalized = normalized.lower()
    for ch in _ZERO_WIDTH_CHARS:
        normalized = normalized.replace(ch, "")
    return " ".join(normalized.split())


def _normalize_text_preserve_case(*parts: str) -> str:
    text = " ".join(part for part in parts if part)
    normalized = unicodedata.normalize("NFKC", text)
    for ch in _ZERO_WIDTH_CHARS:
        normalized = normalized.replace(ch, "")
    return " ".join(normalized.split())


def _compact_text(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text)


def _contains_all(text: str, tokens: Sequence[str]) -> bool:
    return all(token in text for token in tokens)


def _looks_like_placeholder_secret(value: str) -> bool:
    token = value.strip().lower()
    if token in _SECRET_PLACEHOLDERS:
        return True
    return token.startswith("your_") or token.startswith("example_")


def _extract_decodable_base64_tokens(text: str) -> List[str]:
    tokens = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])", text)
    decoded: List[str] = []
    for token in tokens:
        if len(token) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
            candidate = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if candidate:
            decoded.append(candidate)
    return decoded


@dataclass(frozen=True)
class PatternRule:
    regex: Pattern[str]
    severity: Severity
    score: float
    message: str
    value_group: Optional[int] = None
    suppress_placeholder_values: bool = False


class Detector(Protocol):
    name: str

    def detect(self, ctx: SecurityContext) -> List[Finding]:
        ...


class PromptInjectionDetector:
    name = "prompt_injection"

    def __init__(self) -> None:
        self.rules: Tuple[PatternRule, ...] = (
            PatternRule(re.compile(r"ignore( all)? previous instructions", flags=re.IGNORECASE), "high", 0.8, "Instruction override attempt."),
            PatternRule(re.compile(r"(reveal|show|print).{0,120}(system prompt|hidden prompt)", flags=re.IGNORECASE), "high", 0.75, "System prompt exfiltration attempt."),
            PatternRule(re.compile(r"do not follow policy|bypass safety", flags=re.IGNORECASE), "high", 0.8, "Safety bypass request."),
            PatternRule(re.compile(r"developer mode|jailbreak", flags=re.IGNORECASE), "medium", 0.55, "Jailbreak phrasing detected."),
            PatternRule(re.compile(r"(in your next reply|for the next response).{0,120}(ignore|override)", flags=re.IGNORECASE), "high", 0.75, "Multi-turn override phrasing detected."),
        )
        self.token_heuristics: Tuple[Tuple[Tuple[str, ...], Severity, float, str], ...] = (
            (("ignore", "instructions", "above"), "high", 0.7, "Multi-token instruction override heuristic."),
            (("reveal", "system", "prompt"), "high", 0.75, "System prompt exfiltration heuristic."),
            (("next", "reply", "ignore", "instructions"), "high", 0.7, "Multi-turn prompt injection heuristic."),
        )
        self.compact_signatures: Tuple[Tuple[str, Severity, float, str], ...] = (
            ("ignorepreviousinstructions", "high", 0.8, "Compact instruction override signature."),
            ("revealsystemprompt", "high", 0.75, "Compact system prompt exfiltration signature."),
            ("showhiddenprompt", "high", 0.75, "Compact hidden prompt exfiltration signature."),
            ("bypasssafety", "high", 0.8, "Compact safety bypass signature."),
            ("foryournextreplyignore", "high", 0.75, "Compact multi-turn override signature."),
        )

    def detect(self, ctx: SecurityContext) -> List[Finding]:
        text = _normalize_text(ctx.user_input, ctx.model_output)
        compact = _compact_text(text)
        findings: List[Finding] = []
        seen_keys: set[tuple[str, str]] = set()

        for rule in self.rules:
            if rule.regex.search(text):
                dedupe_key = (rule.message, rule.severity)
                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)
                findings.append(
                    Finding(
                        category=self.name,
                        severity=rule.severity,
                        score=rule.score,
                        message=rule.message,
                        detector=self.name,
                        metadata={"method": "regex", "pattern": rule.regex.pattern},
                    )
                )

        for tokens, severity, score, message in self.token_heuristics:
            if _contains_all(text, tokens):
                dedupe_key = (message, severity)
                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)
                findings.append(
                    Finding(
                        category=self.name,
                        severity=severity,
                        score=score,
                        message=message,
                        detector=self.name,
                        metadata={"method": "token", "tokens": ",".join(tokens)},
                    )
                )

        for signature, severity, score, message in self.compact_signatures:
            if signature in compact:
                dedupe_key = (message, severity)
                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)
                findings.append(
                    Finding(
                        category=self.name,
                        severity=severity,
                        score=score,
                        message=message,
                        detector=self.name,
                        metadata={"method": "compact", "signature": signature},
                    )
                )

        return findings


class SecretLeakDetector:
    name = "secret_leakage"

    def __init__(self) -> None:
        self.rules: Tuple[PatternRule, ...] = (
            PatternRule(
                re.compile(r"api[_-]?key\s*[:=]\s*([A-Za-z0-9_\-]{8,})", flags=re.IGNORECASE),
                "critical",
                0.9,
                "API key pattern detected.",
                value_group=1,
                suppress_placeholder_values=True,
            ),
            PatternRule(re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b", flags=re.IGNORECASE), "critical", 0.95, "OpenAI-style secret key pattern detected.", value_group=1),
            PatternRule(re.compile(r"aws_secret_access_key", flags=re.IGNORECASE), "high", 0.8, "AWS secret key identifier detected."),
            PatternRule(re.compile(r"-----begin (rsa|ec|dsa|openssh) private key-----", flags=re.IGNORECASE), "critical", 1.0, "Private key block detected."),
            PatternRule(
                re.compile(r"authorization\s*:\s*bearer\s+([A-Za-z0-9\-_.]{12,})", flags=re.IGNORECASE),
                "high",
                0.8,
                "Bearer token pattern detected.",
                value_group=1,
                suppress_placeholder_values=True,
            ),
            PatternRule(re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", flags=re.IGNORECASE), "high", 0.8, "GitHub token pattern detected."),
            PatternRule(re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", flags=re.IGNORECASE), "high", 0.8, "Slack token pattern detected."),
        )

    def detect(self, ctx: SecurityContext) -> List[Finding]:
        action_targets = [action.target for action in ctx.planned_actions]
        text = _normalize_text(ctx.user_input, ctx.model_output, *action_targets)
        raw_text = _normalize_text_preserve_case(ctx.user_input, ctx.model_output, *action_targets)
        findings: List[Finding] = []

        for rule in self.rules:
            match = rule.regex.search(text)
            if not match:
                continue

            if rule.value_group is not None and rule.suppress_placeholder_values:
                value = match.group(rule.value_group)
                if _looks_like_placeholder_secret(value):
                    continue

            findings.append(
                Finding(
                    category=self.name,
                    severity=rule.severity,
                    score=rule.score,
                    message=rule.message,
                    detector=self.name,
                    metadata={"method": "regex", "pattern": rule.regex.pattern},
                )
            )

        for decoded in _extract_decodable_base64_tokens(raw_text):
            decoded_normalized = _normalize_text(decoded)
            if "sk-" in decoded_normalized and re.search(r"[a-z0-9]{20,}", decoded_normalized):
                findings.append(
                    Finding(
                        category=self.name,
                        severity="high",
                        score=0.85,
                        message="Base64-decoded secret-like token detected.",
                        detector=self.name,
                        metadata={"method": "base64_decode"},
                    )
                )
                break

        return findings


class ToolAbuseDetector:
    name = "tool_abuse"

    def __init__(self, sensitive_actions: Dict[str, Tuple[Severity, float]]) -> None:
        self.sensitive_actions = {k.lower(): v for k, v in sensitive_actions.items()}
        self.indirect_patterns: Tuple[Tuple[Pattern[str], Severity, float, str], ...] = (
            (
                re.compile(r"(read|dump|extract).{0,80}(memory|vault|secrets).{0,120}(send|post|upload|exfiltrat).{0,120}(http|webhook|endpoint)", flags=re.IGNORECASE),
                "high",
                0.8,
                "Indirect tool-abuse exfiltration phrasing detected.",
            ),
            (
                re.compile(r"(first|then).{0,120}(run|execute).{0,80}(shell|command)", flags=re.IGNORECASE),
                "medium",
                0.55,
                "Indirect shell execution orchestration detected.",
            ),
        )

    def detect(self, ctx: SecurityContext) -> List[Finding]:
        findings: List[Finding] = []
        text = _normalize_text(ctx.user_input, ctx.model_output, *(action.target for action in ctx.planned_actions))

        for action in ctx.planned_actions:
            if action.action_type in self.sensitive_actions:
                severity, score = self.sensitive_actions[action.action_type]
                findings.append(
                    Finding(
                        category=self.name,
                        severity=severity,
                        score=score,
                        message=f"Sensitive tool action requested: {action.action_type}",
                        detector=self.name,
                        metadata={"target": action.target},
                    )
                )

        for pattern, severity, score, message in self.indirect_patterns:
            if pattern.search(text):
                findings.append(
                    Finding(
                        category=self.name,
                        severity=severity,
                        score=score,
                        message=message,
                        detector=self.name,
                        metadata={"method": "regex", "pattern": pattern.pattern},
                    )
                )

        return findings


class PolicyDriftDetector:
    name = "policy_drift"

    def __init__(self) -> None:
        self.rules: Tuple[PatternRule, ...] = (
            PatternRule(re.compile(r"new policy:|policy update:", flags=re.IGNORECASE), "medium", 0.5, "Untrusted policy update attempt."),
            PatternRule(re.compile(r"from now on.{0,120}(ignore|override)", flags=re.IGNORECASE), "high", 0.75, "Policy override phrase detected."),
            PatternRule(re.compile(r"trust me|i am admin", flags=re.IGNORECASE), "medium", 0.45, "Authority spoofing phrase detected."),
        )

    def detect(self, ctx: SecurityContext) -> List[Finding]:
        text = _normalize_text(ctx.user_input)
        findings: List[Finding] = []
        for rule in self.rules:
            if rule.regex.search(text):
                findings.append(
                    Finding(
                        category=self.name,
                        severity=rule.severity,
                        score=rule.score,
                        message=rule.message,
                        detector=self.name,
                        metadata={"method": "regex", "pattern": rule.regex.pattern},
                    )
                )
        return findings


def build_detectors(config: FirewallConfig) -> List[Detector]:
    detectors: List[Detector] = []
    if config.detector_toggles.get("prompt_injection", True):
        detectors.append(PromptInjectionDetector())
    if config.detector_toggles.get("secret_leakage", True):
        detectors.append(SecretLeakDetector())
    if config.detector_toggles.get("tool_abuse", True):
        detectors.append(ToolAbuseDetector(dict(config.sensitive_actions)))
    if config.detector_toggles.get("policy_drift", True):
        detectors.append(PolicyDriftDetector())
    return detectors
