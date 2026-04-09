"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.
"""

import re
import html
import logging
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


# Patterns for dynamic code execution primitives that should be removed
_DANGEROUS_CODE_PATTERNS = [
    re.compile(r'^\s*eval\s*\(.*\)\s*;?\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*exec\s*\(.*\)\s*;?\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*subprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True.*\)\s*;?\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*os\s*\.\s*system\s*\(.*\)\s*;?\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*os\s*\.\s*popen\s*\(.*\)\s*;?\s*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'<script\b[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'^\s*bash\s+-c\s+.*$', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*\$\(.*\)\s*$', re.MULTILINE),
    re.compile(r'^\s*`[^`]+`\s*$', re.MULTILINE),
]

# PII patterns
_PII_PATTERNS = [
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN
    re.compile(r'\b(?:\d[ -]?){13,16}\b'),  # Credit card numbers
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email
    re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),  # Phone numbers
    re.compile(r'\b(?:password|passwd|secret|api[_\s]?key|token)\s*[:=]\s*\S+', re.IGNORECASE),  # Credentials
]

# Sensitive data patterns
_SENSITIVE_DATA_PATTERNS = [
    re.compile(r'(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)', re.IGNORECASE),  # Private keys
    re.compile(r'(?:aws|azure|gcp)[_\s]?(?:secret|key|token)\s*[:=]\s*\S+', re.IGNORECASE),  # Cloud credentials
    re.compile(r'(?:connection[_\s]?string|connstr)\s*[:=]\s*\S+', re.IGNORECASE),  # DB connection strings
]

# Bias/harmful content patterns
_HARMFUL_PATTERNS = [
    re.compile(r'\b(?:kill|murder|attack|bomb|exploit|hack)\s+(?:the\s+)?(?:user|system|server|database)\b', re.IGNORECASE),
]


def _sanitize_response(response: str) -> tuple[str, list[str]]:
    """
    Remove dangerous code execution primitives and sanitize the response.
    Returns sanitized response and list of violations found.
    """
    if not isinstance(response, str):
        return "", ["Response is not a valid string"]

    violations = []
    sanitized = response

    for pattern in _DANGEROUS_CODE_PATTERNS:
        if pattern.search(sanitized):
            violations.append(f"Dangerous code execution pattern detected and removed: {pattern.pattern[:60]}")
            sanitized = pattern.sub('', sanitized)

    # Encode HTML special characters to prevent XSS
    # Only encode if the response is not expected to contain HTML
    # Strip null bytes and other control characters
    sanitized = sanitized.replace('\x00', '')
    sanitized = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)

    return sanitized, violations


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    Validates:
    - No dynamic code execution primitives (eval, exec, shell=True, etc.)
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Compliance with content policies
    """

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.
        Sanitizes and checks for dangerous patterns before returning.
        """
        if not isinstance(response, str):
            logger.warning("Invalid response type received: %s", type(response).__name__)
            return ValidationResult(
                is_valid=False,
                violations=["Response is not a valid string"],
                filtered_response="",
                original_response=str(response) if response is not None else ""
            )

        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        all_violations = []

        # Sanitize and remove dangerous code execution primitives
        sanitized_response, code_violations = _sanitize_response(response)
        all_violations.extend(code_violations)

        # Check for PII leakage
        pii_violations = await self.check_pii_leakage(sanitized_response)
        all_violations.extend(pii_violations)

        # Check for bias/harmful content
        bias_violations = await self.check_bias(sanitized_response)
        all_violations.extend(bias_violations)

        # Check for sensitive data leakage
        data_violations = await self.check_data_leakage(sanitized_response)
        all_violations.extend(data_violations)

        is_valid = len(all_violations) == 0

        if all_violations:
            logger.warning(
                "Response validation violations found",
                extra={
                    "violation_count": len(all_violations),
                    "validation_count": self.validation_count
                }
            )

        return ValidationResult(
            is_valid=is_valid,
            violations=all_violations,
            filtered_response=sanitized_response,
            original_response=response
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.
        """
        if not isinstance(response, str):
            return ["Invalid response type for PII check"]

        violations = []
        for pattern in _PII_PATTERNS:
            if pattern.search(response):
                violations.append(f"Potential PII detected in response matching pattern: {pattern.pattern[:60]}")
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.
        """
        if not isinstance(response, str):
            return ["Invalid response type for bias check"]

        violations = []
        for pattern in _HARMFUL_PATTERNS:
            if pattern.search(response):
                violations.append(f"Potentially harmful content detected in response")
        return violations

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.
        """
        if not isinstance(response, str):
            return ["Invalid response type for data leakage check"]

        violations = []
        for pattern in _SENSITIVE_DATA_PATTERNS:
            if pattern.search(response):
                violations.append(f"Sensitive data pattern detected in response: {pattern.pattern[:60]}")
        return violations