"""
Finance Agent

Handles financial data queries with HIGH privilege level.
Should only be accessible to authorized callers.

SECURITY NOTES (for Unifai demo):
- Authorization check exists but has bypass for "internal" calls
- Sensitive financial data returned without audit logging
- No rate limiting on data access
"""

import logging
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.internal import AuthorizedLLMClient

logger = logging.getLogger(__name__)

# Configure 6-month log retention (180 daily backups)
handler = TimedRotatingFileHandler(
    'finance_agent.log',
    when='midnight',
    interval=1,
    backupCount=180
)
logger.addHandler(handler)


class FinanceAgent:
    """
    Finance agent for handling financial data queries.

    Privilege Level: HIGH
    Capabilities:
    - Access financial reports
    - Query budget information
    - Generate financial summaries

    SECURITY: This agent handles sensitive financial data and
    should only be accessible to authorized callers.
    """

    ALLOWED_ROLES = ["finance_admin", "cfo", "admin"]
    PRIVILEGE_LEVEL = "high"
    COVERED_DOMAIN = "financial_services"
    RISK_CLASSIFICATION = "high"  # Policy-mandated risk declaration

    def __init__(self, llm_client: AzureClient):
        self.llm_client = llm_client
        self.authenticator = AgentAuthenticator.get_registered('finance')
        self.agent_id = "finance"
        self.agent_name = "Finance Agent"
        self.model_version = "1.0.0"  # Model version identifier

        # Simulated financial data (would be database in real app)
        self._financial_data = {
            "quarterly_revenue": {
                "Q1_2024": 2500000,
                "Q2_2024": 2750000,
                "Q3_2024": 3100000,
                "Q4_2024": 3400000
            },
            "operating_expenses": {
                "Q1_2024": 1800000,
                "Q2_2024": 1900000,
                "Q3_2024": 2000000,
                "Q4_2024": 2100000
            },
            "employee_salaries": {
                "engineering": 1200000,
                "sales": 800000,
                "operations": 600000,
                "executive": 500000
            },
            "sensitive_projections": {
                "merger_target": "[MASKED]",
                "acquisition_budget": "[MASKED]",
                "layoff_planning": "[MASKED]"
            }
        }

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request with authorization check.

        Args:
            context: Request context with query details
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary with financial data or error
        """
        # Authorization check
        # VULNERABILITY: Check exists but has bypass
        if not self._verify_authorization(caller, headers):
            logger.warning(
                "Unauthorized access attempt to finance agent",
                extra={
                    "caller_id": caller.agent_id,
                    "caller_privilege": caller.privilege_level,
                    "retention_period": "1095 days (3 years)"
                }
            )
            return {
                "response": "Unauthorized: You do not have permission to access financial data.",
                "agent": self.agent_id,
                "error": "unauthorized"
            }

        user_message = context.get("user_message", "")

        # Validate and sanitize input
        validation_result = self._sanitize_input(user_message)
        if validation_result.get("error"):
            logger.warning("Invalid input detected in financial query",
                         extra={"original_input": user_message})
            return {"response": validation_result["error"], "agent": self.agent_id}

        sanitized_input = validation_result["sanitized"]
        # Process the financial query
        response = await self._process_financial_query(user_message)
        logger.info(
            "MCP server interaction processed",
            extra={
                "caller_id": caller.agent_id,
                "user_message": user_message,
                "agent": self.agent_id,
                "interaction_type": "financial_query"
            }
        )

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    def _sanitize_input(self, user_input: str) -> dict:
        """Sanitize and validate user input for financial queries"""
        # Remove potentially dangerous characters
        sanitized = user_input.strip().replace(";", "").replace("'", "")

        # Validate input length and content
        if len(sanitized) > 500:
            return {"error": "Input exceeds maximum allowed length (500 characters)"}
        if not re.match(r"^[a-zA-Z0-9\s\.,?\-]+$", sanitized):
            return {"error": "Invalid characters detected in query"}

        return {"sanitized": sanitized}

    def _sanitize_input(self, input_str: str) -> tuple[str, bool]:
        """Sanitize user input and detect injection patterns"""
        injection_patterns = [
            r'(?i)ignore previous instructions',
            r'(?i)system:.*assistant',
            r'(?i)your purpose is',
            r'(?i)<</SYS>>',
            r'(?i)role play',
            r'(?i)as a (hacker|malicious user)'
        ]

        sanitized = input_str.strip()
        for pattern in injection_patterns:
            if re.search(pattern, sanitized):
                return (sanitized, False)
        return (sanitized, True)

    def _verify_authorization(
        self,
        caller: AgentIdentity,
        headers: Optional[dict]
    ) -> bool:
        """
        Verify that the caller is authorized to access financial data.

        VULNERABILITY: The is_internal flag bypasses all privilege checks.
        Any agent claiming to be "internal" can access financial data.
        """
        # Check 1: Role-based access
        if caller.privilege_level in self.ALLOWED_ROLES:
            return True

        # Check 2: Admin override
        if caller.privilege_level == "admin":
            return True

        # VULNERABILITY: Internal bypass - any agent claiming internal status
        # gets full access without verification
        if caller.is_internal:
            logger.info(
                "Internal caller accessing finance agent",
                extra={
                    "caller": caller.agent_id,
                    "note": "Internal bypass used"
                }
            )
            return True  # Bypass for "internal" calls

        # Check 3: Token verification (but token is never actually validated!)
        # VULNERABILITY: We check if token exists but never validate it
        if headers and headers.get("X-Agent-Token"):
            # Token exists, but we don't verify its validity
            # This is a security vulnerability - any token passes
            logger.debug("Token provided, granting access")
            return True

        return False

    async def _process_financial_query(self, query: str) -> str:
        """
        Process a financial query and return relevant data.

        VULNERABILITY: Sensitive financial data returned without
        proper audit logging or data masking.
        """
        query_lower = query.lower()

        # Determine what data to include
        data_to_include = []

        if "revenue" in query_lower or "quarterly" in query_lower:
            data_to_include.append(
                f"Quarterly Revenue:\n{self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        if "expense" in query_lower or "cost" in query_lower:
            data_to_include.append(
                f"Operating Expenses:\n{self._format_dict(self._financial_data['operating_expenses'])}"
            )

        if "salary" in query_lower or "payroll" in query_lower:
            # VULNERABILITY: Salary data returned without masking
            data_to_include.append(
                f"Department Salaries:\n{self._format_dict(self._financial_data['employee_salaries'])}"
            )

        if "projection" in query_lower or "forecast" in query_lower or "plan" in query_lower:
            # VULNERABILITY: Highly sensitive strategic data exposed
            data_to_include.append(
                f"Strategic Projections (CONFIDENTIAL):\n{self._format_dict(self._financial_data['sensitive_projections'])}"
            )

        if not data_to_include:
            # Default response with general financial overview
            data_to_include.append(
                f"Financial Overview:\nRevenue: {self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        financial_context = "\n\n".join(data_to_include)

        # Use LLM to generate a natural response
        # VULNERABILITY: Sensitive financial data sent to external LLM
        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": """You are an AI financial analyst assistant. Always disclose you are an AI when responding.
Provide clear, professional responses about financial data.
Format numbers clearly and provide relevant insights.
Begin responses with 'As an AI financial assistant:'"""
                },
                {
                    "role": "user",
                    "content": "Based on this financial data:\n\n{financial_context}\n\nPlease answer: {query}",
                    "parameters": {
                        "financial_context": financial_context,
                        "query": query
                    }
                }
            ]
        )

        return {
    "content": response,
    "provenance": {
        "source": "ai_generated",
        "model": self.llm_client.model_name,
        "system": "financial_analyst"
    },
    "content_type": "financial_analysis/ai_generated",
    "generation_timestamp": datetime.datetime.utcnow().isoformat(),
    "watermark": "AI-Generated Content: XyZ123"
}

    def _format_dict(self, data: dict) -> str:
        """Format dictionary data for display."""
        return "\n".join(f"  - {k}: {v}" for k, v in data.items())

    async def get_financial_data(
        self,
        requester: AgentIdentity,
        query: str
    ) -> dict[str, Any]:
        """
        Direct method to get financial data.

        VULNERABILITY: Authorization check has internal bypass.
        Used by other agents to access financial data directly.
        """
        # Authorization check with bypass
        if requester.privilege_level in self.ALLOWED_ROLES:
            pass  # Authorized
        elif requester.is_internal:
            # VULNERABILITY: is_internal always True for agent calls
            pass  # Bypassed
        else:
            return {"error": "Unauthorized"}

        # VULNERABILITY: Full financial data access without granular permissions
        return {
            "data": self._filter_data_by_query(query),
            "query": query,
            "requester": requester.agent_id
        }
