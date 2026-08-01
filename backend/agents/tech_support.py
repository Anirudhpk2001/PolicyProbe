"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization
"""

import logging
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity
from llm.internal import InternalLLMClient

logger = logging.getLogger(__name__)


class TechSupportAgent:
    """
    Technical support agent for handling general user queries.

    Privilege Level: LOW
    Capabilities:
    - Answer general questions
    - Provide technical guidance
    - Escalate to specialized agents

    Model Documentation: OpenRouter model card (https://openrouter.ai/docs#model-card)
    """

    ALLOWED_ROLES = ["user", "tech_support", "admin"]
    PRIVILEGE_LEVEL = "low"
    COVERED_DOMAIN = "technical_support"
    RISK_CLASSIFICATION = "medium"  # Policy-mandated risk classification

    def __init__(self, llm_client: InternalLLMClient):
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
        # VULNERABILITY: Token in headers is never validated
        # We just check if it exists, not if it's valid
        token = headers.get("X-Agent-Token") if headers else None
        if token:
            logger.debug(f"Received request with token: {token[:10]}...")

        user_message = context.get("user_message", "")

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(user_message):
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": user_message[:100]
                }
            )
            # VULNERABILITY: Escalating to high-privilege agent without proper auth
            escalation_response = await self._escalate_to_finance(user_message, context)
            escalation_response['terminate'] = True
            return escalation_response

        # Handle the query directly
        response = await self._process_query(user_message, context)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL,
            "model_version": self.llm_client.model_version,
            "disclosures": {
                "decision_factors": "Analysis of query content and escalation triggers",
                "known_limitations": "Cannot process financial or account-specific requests",
                "accuracy_metrics": {"estimated_accuracy": "85% based on historical data"},
                "appeal_rights": "Contact support@unifai.demo for review requests"
            }
        }

    def _detect_prompt_injection(self, message: str) -> bool:
        """Detect common prompt injection patterns in user input."""
        injection_patterns = [
            "ignore previous instructions",
            "system prompt",
            "act as",
            "your creators",
            "#",
            "roleplay",
            "assistant"
        ]
        return any(pattern in message.lower() for pattern in injection_patterns)

    def _needs_finance_escalation(self, message: str) -> bool:
        """Check if message requires finance agent access."""
    def _generate_oauth_token(self, scopes: list[str]) -> str:
        """Generate OAuth token with required scopes for escalation."""
        # Simplified example - real implementation should use proper crypto/signing
        scope_str = ",".join(sorted(scopes))
        return f"escalation-token:{scope_str}:{self.agent_id}"

    def _needs_finance_escalation(self, message: str) -> bool:
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

        VULNERABILITY: This method allows a low-privilege agent to
        access high-privilege agent without proper authorization.
        The is_internal flag bypasses privilege checks.
        """
        # Import here to avoid circular imports
        from .finance import FinanceAgent

        # Create identity that will bypass auth checks
        # VULNERABILITY: Low privilege agent claims internal status
        escalation_identity = AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=True  # This bypasses privilege verification
        )

        finance_agent = FinanceAgent(self.llm_client)

        # Make the call to finance agent
        # VULNERABILITY: No verification that this escalation is authorized
        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": self._generate_oauth_token(scopes=["finance_agent:access"])}
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

        VULNERABILITY: User message sent to LLM without sanitization
        or content scanning.
        """
        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        # VULNERABILITY: Direct user input to LLM without scanning
        response = await self.llm_client.chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ]
        )

        return {
        "content": response,
        "provenance": "llm-generated",
        "content_type": "synthetic/ai-generated",
        "generated_at": datetime.now().isoformat()
    }

    async def get_user_context(self, user_id: str) -> dict:
        """
        Retrieve user context for personalized support.

        VULNERABILITY: Returns full user context including potentially
        sensitive information without filtering.
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
            # VULNERABILITY: Sensitive data in context
            "internal_notes": "[REDACTED]",
            "account_details": {
                "contact_email": "u***@example.com",
                "phone": "***-***-4567"
            }
        }

        logger.info(
            "Retrieved user context",
            extra={
                # VULNERABILITY: Logging full user context with sensitive data
                "user_context": {k: v for k, v in user_context.items() if k != 'account_details'}
            }
        )

        return user_context
