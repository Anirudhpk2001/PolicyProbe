"""
Audit Logger

Provides audit logging for security-relevant events.
"""

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

_AUDIT_HMAC_KEY = os.environ.get("AUDIT_HMAC_KEY", os.urandom(32))


def _compute_integrity_tag(event: dict) -> str:
    """Compute an HMAC tag for an audit event to detect tampering."""
    serialized = json.dumps(event, sort_keys=True, default=str).encode("utf-8")
    key = _AUDIT_HMAC_KEY if isinstance(_AUDIT_HMAC_KEY, bytes) else _AUDIT_HMAC_KEY.encode("utf-8")
    return hmac.new(key, serialized, hashlib.sha256).hexdigest()


def _sanitize_value(value: Any) -> Any:
    """Recursively sanitize values to prevent log injection."""
    if isinstance(value, str):
        return value.replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "")
    if isinstance(value, dict):
        return {_sanitize_value(k): _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(i) for i in value]
    return value


class AuditLogger:
    """
    Audit logging for security events.

    Provides:
    - Tamper-evident audit trail via HMAC integrity tags
    - Log injection prevention
    - Structured event logging
    - Severity-based alerting hooks
    """

    def __init__(self):
        self._events = []

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> None:
        """
        Log a security-relevant event with tamper-evident integrity tag.
        """
        allowed_severities = {"debug", "info", "warning", "error", "critical"}
        if severity not in allowed_severities:
            severity = "info"

        sanitized_event_type = _sanitize_value(event_type)
        sanitized_details = _sanitize_value(details)
        sanitized_user_id = _sanitize_value(user_id) if user_id is not None else None

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": sanitized_event_type,
            "details": sanitized_details,
            "user_id": sanitized_user_id,
            "severity": severity
        }

        integrity_tag = _compute_integrity_tag(event)
        event["integrity_tag"] = integrity_tag

        self._events.append(event)

        log_fn = getattr(logger, severity, logger.info)
        log_fn(
            "Audit: %s",
            sanitized_event_type,
            extra={k: v for k, v in event.items() if k != "integrity_tag"}
        )

        if severity in ("error", "critical"):
            self._trigger_alert(event)

    def _trigger_alert(self, event: dict) -> None:
        """
        Hook for high-severity alert integration.
        Override or extend to integrate with alerting systems.
        """
        logger.critical(
            "SECURITY ALERT: High-severity audit event detected: %s",
            event.get("type", "unknown")
        )

    async def log_policy_violation(
        self,
        policy_type: str,
        violation_details: dict
    ) -> None:
        """
        Log a policy violation with warning severity.
        """
        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": policy_type,
                **violation_details
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
        Log data access for compliance.
        """
        await self.log_event(
            event_type="data_access",
            details={
                "resource": resource,
                "action": action
            },
            user_id=user_id
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Get recent audit events."""
        if not isinstance(count, int) or count < 1:
            count = 100
        count = min(count, 1000)
        return self._events[-count:]

    def verify_event_integrity(self, event: dict) -> bool:
        """Verify the integrity tag of a stored audit event."""
        stored_tag = event.get("integrity_tag")
        if not stored_tag:
            return False
        event_without_tag = {k: v for k, v in event.items() if k != "integrity_tag"}
        expected_tag = _compute_integrity_tag(event_without_tag)
        return hmac.compare_digest(stored_tag, expected_tag)