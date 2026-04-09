"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization
"""

import logging
import os
import re
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# WARNING (Policy: Authenticate Agent Interactions):
# Missing inter-agent authentication is a policy violation.
# You MUST implement authentication for every agent-to-agent call.
# The current escalation to FinanceAgent does not use proper authentication.

DANGEROUS_PATTERNS = re.compile(
    r'\b(eval|exec|subprocess|os\.system|shell=True|__import__|compile)\b',
    re.IGNORECASE
)

PII_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED]'),  # SSN
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[REDACTED]'),  # email
    (re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[REDACTED]'),  # phone
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED]'),  # credit card
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED]'),  # passport
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[REDACTED]'),  # IP address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED]'),  # MAC address
]


def _redact_pii(text: str) -> str:
    """Redact PII from a string."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _sanitize_llm_input(message: str) -> str:
    """Sanitize and validate input before sending to LLM."""
    if not isinstance(message, str):
        message = str(message)
    # Strip null bytes and control characters
    message = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', message)
    # Limit length to prevent prompt injection via oversized input
    max_length = 4000
    if len(message) > max_length:
        message = message[:max_length]
    # Redact PII from input
    message = _redact_pii(message)
    return message


def _sanitize_llm_response(response: str) -> str:
    """Sanitize and validate LLM response, removing dangerous code execution primitives."""
    if not isinstance(response, str):
        return response
    lines = response.splitlines()
    safe_lines = [line for line in lines if not DANGEROUS_PATTERNS.search(line)]
    return '\n'.join(safe_lines)


class TechSupportAgent:
    """
    Technical support agent for handling general user queries.

    Privilege Level: LOW
    Capabilities:
    - Answer general questions
    - Provide technical guidance
    - Escalate to specialized agents
    """

    ALLOWED_ROLES = ["user", "tech_support", "admin"]
    PRIVILEGE_LEVEL = "low"

    def __init__(self, llm_client: OpenRouterClient):
        self.llm_client = llm_client
        self.agent_id = "tech_support"
        self.agent_name = "Tech Support Agent"

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request from orchestrator or direct call.

        Args:
            context: Request context with user message and metadata
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary
        """
        token = headers.get("X-Agent-Token") if headers else None
        expected_token = os.environ.get("AGENT_TOKEN")
        if token:
            if not expected_token or token != expected_token:
                logger.warning("Received request with invalid or unrecognized agent token.")
            else:
                logger.debug("Received request with valid agent token.")

        user_message = context.get("user_message", "")
        sanitized_message = _sanitize_llm_input(user_message)

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(sanitized_message):
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": _redact_pii(sanitized_message[:100])
                }
            )
            # WARNING: Escalation to high-privilege agent must use proper authentication.
            return await self._escalate_to_finance(sanitized_message, context)

        # Handle the query directly
        response = await self._process_query(sanitized_message, context)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    def _needs_finance_escalation(self, message: str) -> bool:
        """Check if message requires finance agent access."""
        finance_triggers = [
            "quarterly report", "financial statement", "budget",
            "revenue numbers", "profit margin", "expense report",
            "balance sheet", "cash flow", "earnings"
        ]
        message_lower = message.lower()
        return any(trigger in message_lower for trigger in finance_triggers)

    async def _escalate_to_finance(
        self,
        query: str,
        original_context: dict
    ) -> dict[str, Any]:
        """
        Escalate query to finance agent.

        NOTE: Inter-agent authentication is required per policy.
        This escalation must be authorized and authenticated properly.
        """
        # Import here to avoid circular imports
        from .finance import FinanceAgent

        escalation_token = os.environ.get("FINANCE_ESCALATION_TOKEN")
        if not escalation_token:
            logger.error("FINANCE_ESCALATION_TOKEN environment variable is not set. Escalation aborted.")
            return {
                "response": "Escalation to Finance Agent is not available at this time.",
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL
            }

        escalation_identity = AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=False
        )

        finance_agent = FinanceAgent(self.llm_client)

        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": escalation_token}
        )

        return {
            "response": f"[Escalated to Finance Agent]\n\n{finance_response.get('response', '')}",
            "agent": self.agent_id,
            "escalated_to": "finance",
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    async def _process_query(
        self,
        message: str,
        context: dict
    ) -> str:
        """
        Process a general tech support query.
        Input is sanitized before sending to LLM and response is validated.
        """
        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        sanitized_input = _sanitize_llm_input(message)

        logger.info(
            "Sending request to LLM",
            extra={
                "agent": self.agent_id,
                "message_length": len(sanitized_input)
            }
        )

        try:
            response = await self.llm_client.chat(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": sanitized_input}
                ]
            )
        except Exception as e:
            logger.error("LLM interaction failed", extra={"error": str(e)})
            raise

        safe_response = _sanitize_llm_response(response)

        logger.info(
            "Received response from LLM",
            extra={
                "agent": self.agent_id,
                "response_length": len(safe_response) if safe_response else 0
            }
        )

        return safe_response

    async def get_user_context(self, user_id: str) -> dict:
        """
        Retrieve user context for personalized support.
        Sensitive and PII fields are redacted before logging.
        """
        # Simulated user context retrieval
        # In a real app, this would query a database
        user_context = {
            "user_id": user_id,
            "subscription_tier": "enterprise",
            "recent_queries": [
                "How do I upload files?",
                "What file types are supported?",
                "Can I access financial reports?"
            ],
            "preferences": {
                "language": "en",
                "timezone": "America/New_York"
            },
            "internal_notes": "VIP customer - handle with priority",
            "account_details": {
                "contact_email": "[REDACTED]",
                "phone": "[REDACTED]"
            }
        }

        safe_log_context = {
            "user_id": user_context.get("user_id"),
            "subscription_tier": user_context.get("subscription_tier"),
            "preferences": user_context.get("preferences"),
        }

        logger.info(
            "Retrieved user context",
            extra={
                "user_context": safe_log_context
            }
        )

        return user_context