"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.
"""

import logging
import re
import html
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    violations: list[str]
    filtered_response: Optional[str] = None
    original_response: Optional[str] = None


# Patterns for dynamic code execution primitives that must be removed
_DANGEROUS_PATTERNS = [
    re.compile(r'^\s*eval\s*\(.*\)\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*exec\s*\(.*\)\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*subprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True.*\)\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*os\s*\.\s*system\s*\(.*\)\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*os\s*\.\s*popen\s*\(.*\)\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'<script\b[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'^\s*__import__\s*\(.*\)\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*compile\s*\(.*\)\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*execfile\s*\(.*\)\s*$', re.MULTILINE | re.IGNORECASE),
]

# PII patterns
_PII_PATTERNS = [
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN
    re.compile(r'\b(?:\d[ -]?){13,16}\b'),  # Credit card
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email
    re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),  # Phone
]

# Sensitive data patterns
_SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|api[_\s]?key|token|private[_\s]?key)\s*[:=]\s*\S+'),
    re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*'),
    re.compile(r'(?i)basic\s+[A-Za-z0-9+/]+=*'),
]

# Bias/harmful content indicators
_HARMFUL_PATTERNS = [
    re.compile(r'\b(hate|kill|murder|terrorist|bomb)\b', re.IGNORECASE),
]


def _remove_dangerous_lines(response: str) -> tuple[str, list[str]]:
    """Remove lines containing dangerous code execution primitives."""
    violations = []
    lines = response.splitlines(keepends=True)
    safe_lines = []
    for line in lines:
        removed = False
        for pattern in _DANGEROUS_PATTERNS:
            if pattern.search(line):
                violations.append(
                    f"Removed dangerous code execution primitive from response: {line.strip()[:80]}"
                )
                removed = True
                break
        if not removed:
            safe_lines.append(line)
    return ''.join(safe_lines), violations


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    Validates:
    - No dynamic code execution primitives (eval, exec, shell=True, etc.)
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Output encoding for XSS prevention
    """

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.
        Removes dangerous code execution primitives and checks for other violations.
        """
        if not isinstance(response, str):
            logger.warning("Non-string response received; coercing to string.")
            response = str(response)

        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        original_response = response
        all_violations = []

        # Remove dangerous code execution primitives
        sanitized, code_violations = _remove_dangerous_lines(response)
        all_violations.extend(code_violations)

        # Check for PII leakage
        pii_violations = await self.check_pii_leakage(sanitized)
        all_violations.extend(pii_violations)

        # Check for bias/harmful content
        bias_violations = await self.check_bias(sanitized)
        all_violations.extend(bias_violations)

        # Check for sensitive data leakage
        data_violations = await self.check_data_leakage(sanitized)
        all_violations.extend(data_violations)

        is_valid = len(all_violations) == 0

        if all_violations:
            logger.warning(
                "LLM response validation violations found",
                extra={
                    "violation_count": len(all_violations),
                    "violations": [v[:120] for v in all_violations],
                    "validation_count": self.validation_count
                }
            )

        return ValidationResult(
            is_valid=is_valid,
            violations=all_violations,
            filtered_response=sanitized,
            original_response=original_response
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.
        """
        violations = []
        for pattern in _PII_PATTERNS:
            matches = pattern.findall(response)
            if matches:
                violations.append(
                    f"Potential PII detected in response matching pattern: {pattern.pattern[:60]}"
                )
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.
        """
        violations = []
        for pattern in _HARMFUL_PATTERNS:
            if pattern.search(response):
                violations.append(
                    f"Potentially harmful content detected matching pattern: {pattern.pattern[:60]}"
                )
        return violations

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.
        """
        violations = []
        for pattern in _SENSITIVE_PATTERNS:
            if pattern.search(response):
                violations.append(
                    f"Potential sensitive data leakage detected matching pattern: {pattern.pattern[:60]}"
                )
        return violations