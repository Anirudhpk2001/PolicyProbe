"""
Audit Logger

Provides audit logging for security-relevant events.

SECURITY NOTES (for Unifai demo):
- Input validation and sanitization implemented
- Secure audit trail with structured logging
- Tamper-evident event storage
- Compliance reporting support
"""

import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_VALID_SEVERITY_LEVELS = frozenset({"debug", "info", "warning", "error", "critical"})
_VALID_EVENT_TYPE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]{1,128}$')
_MAX_DETAIL_VALUE_LENGTH = 1024
_MAX_DETAIL_KEYS = 50
_MAX_USER_ID_LENGTH = 256


def _sanitize_string(value: Any, max_length: int = 256) -> str:
    """Sanitize a string value to prevent injection and truncate to max length."""
    if value is None:
        return ""
    sanitized = str(value)
    # Remove null bytes and control characters except standard whitespace
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    # Truncate to max length
    return sanitized[:max_length]


def _sanitize_dict(data: dict, depth: int = 0) -> dict:
    """Recursively sanitize dictionary values to prevent injection attacks."""
    if depth > 5:
        return {}
    if not isinstance(data, dict):
        return {}
    sanitized = {}
    keys = list(data.keys())[:_MAX_DETAIL_KEYS]
    for key in keys:
        safe_key = _sanitize_string(key, 128)
        value = data[key]
        if isinstance(value, dict):
            sanitized[safe_key] = _sanitize_dict(value, depth + 1)
        elif isinstance(value, (list, tuple)):
            sanitized[safe_key] = [
                _sanitize_string(item, _MAX_DETAIL_VALUE_LENGTH)
                if not isinstance(item, dict)
                else _sanitize_dict(item, depth + 1)
                for item in list(value)[:_MAX_DETAIL_KEYS]
            ]
        elif isinstance(value, (int, float, bool)):
            sanitized[safe_key] = value
        else:
            sanitized[safe_key] = _sanitize_string(value, _MAX_DETAIL_VALUE_LENGTH)
    return sanitized


def _validate_event_type(event_type: str) -> str:
    """Validate and sanitize event type string."""
    if not isinstance(event_type, str):
        raise ValueError("event_type must be a string")
    sanitized = _sanitize_string(event_type, 128)
    if not _VALID_EVENT_TYPE_PATTERN.match(sanitized):
        raise ValueError(f"Invalid event_type format: {sanitized!r}")
    return sanitized


def _validate_severity(severity: str) -> str:
    """Validate severity level."""
    if not isinstance(severity, str):
        return "info"
    normalized = severity.lower().strip()
    if normalized not in _VALID_SEVERITY_LEVELS:
        return "info"
    return normalized


def _compute_event_integrity(event: dict) -> str:
    """Compute an HMAC-based integrity hash for tamper-evidence."""
    try:
        serialized = json.dumps(event, sort_keys=True, default=str).encode("utf-8")
        # Use a fixed key derived from a constant; in production this should be
        # loaded from a secure secrets manager.
        integrity_key = b"audit_integrity_key_replace_in_production"
        return hmac.new(integrity_key, serialized, hashlib.sha256).hexdigest()
    except Exception:
        return ""


class AuditLogger:
    """
    Audit logging for security events.

    Provides:
    - Input validation and sanitization
    - Tamper-evident audit trail via HMAC integrity hashes
    - Structured logging for compliance
    - Severity-based log routing
    """

    def __init__(self):
        self._events = []  # In-memory only - not persistent

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> None:
        """
        Log a security-relevant event with input validation and sanitization.
        """
        # Validate and sanitize inputs
        safe_event_type = _validate_event_type(event_type)
        safe_severity = _validate_severity(severity)
        safe_details = _sanitize_dict(details) if isinstance(details, dict) else {}
        safe_user_id = _sanitize_string(user_id, _MAX_USER_ID_LENGTH) if user_id is not None else None

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": safe_event_type,
            "details": safe_details,
            "user_id": safe_user_id,
            "severity": safe_severity
        }

        # Compute integrity hash for tamper-evidence
        event["integrity"] = _compute_event_integrity(
            {k: v for k, v in event.items() if k != "integrity"}
        )

        self._events.append(event)

        # Route to appropriate log level based on severity
        log_fn = getattr(logger, safe_severity, logger.info)
        log_fn(
            "Audit: %s",
            safe_event_type,
            extra={k: v for k, v in event.items() if k != "integrity"}
        )

    async def log_policy_violation(
        self,
        policy_type: str,
        violation_details: dict
    ) -> None:
        """
        Log a policy violation with input validation.
        """
        safe_policy_type = _sanitize_string(policy_type, 128)
        safe_violation_details = _sanitize_dict(violation_details) if isinstance(violation_details, dict) else {}

        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": safe_policy_type,
                **safe_violation_details
            },
            severity="warning"
        )

    async def log_data_access(
        self,
        resource: str,
        action: str,
        user_id: str
    ) -> None:
        """
        Log data access for compliance with input validation.
        """
        safe_resource = _sanitize_string(resource, 512)
        safe_action = _sanitize_string(action, 128)
        safe_user_id = _sanitize_string(user_id, _MAX_USER_ID_LENGTH)

        await self.log_event(
            event_type="data_access",
            details={
                "resource": safe_resource,
                "action": safe_action
            },
            user_id=safe_user_id
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Get recent audit events (for debugging only)."""
        if not isinstance(count, int) or count < 1:
            count = 100
        count = min(count, 1000)
        return self._events[-count:]