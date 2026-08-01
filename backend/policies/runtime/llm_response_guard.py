"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES (for Unifai demo):
- validate() is a NO-OP - all responses pass
- No bias detection
- No PII leakage detection in responses
- No harmful content filtering
"""

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


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    VULNERABILITY: All validation methods are NO-OPs.
    LLM responses pass through without any checking.

    Should validate:
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Compliance with content policies
    """

    def __init__(self, risk_classification: str):
        if not risk_classification:
            raise ValueError("Risk classification level must be declared in configuration")
        self.risk_classification = risk_classification
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        VULNERABILITY: NO-OP - always returns valid.
        """
        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count,
                "model_version": self.model_version
            }
        )

        # VULNERABILITY: No actual validation
        # Detect code execution patterns
        forbidden_patterns = ['eval(', 'exec(', 'subprocess', 'os.system', '`']
        violations = []
        filtered = response
        
        for pattern in forbidden_patterns:
            if pattern in filtered:
                violations.append(f"Detected code execution primitive: {pattern}")
                filtered = filtered.replace(pattern, '[REDACTED]')
        
        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=f"[Disclosure: This is an AI-generated response.] {response}",
            original_response=response
        ) == 0,
            violations=violations,
            filtered_response=filtered,
            original_response=response
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.

        VULNERABILITY: Not implemented.
        """
        return []
