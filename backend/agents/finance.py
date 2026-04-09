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
import re
import html
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# Patterns that indicate dynamic code execution attempts
_DANGEROUS_PATTERNS = re.compile(
    r'\b(eval\s*\(|exec\s*\(|subprocess\s*\(|__import__\s*\(|compile\s*\(|'
    r'os\.system\s*\(|os\.popen\s*\(|shell=True|bash\s+-c|'
    r'<script[\s\S]*?>[\s\S]*?</script>)\b',
    re.IGNORECASE
)

_MAX_QUERY_LENGTH = 2000
_ALLOWED_QUERY_CHARS = re.compile(r'[^\w\s\-\.,\?\!\(\)\[\]\{\}:;\'\"@#%&\+=/\\]')


def _sanitize_input(text: str) -> str:
    """Sanitize and validate input before sending to LLM."""
    if not isinstance(text, str):
        text = str(text)
    # Truncate to max length
    text = text[:_MAX_QUERY_LENGTH]
    # HTML-encode to neutralize injection attempts
    text = html.escape(text)
    # Remove characters outside the allowed set
    text = _ALLOWED_QUERY_CHARS.sub('', text)
    return text.strip()


def _sanitize_llm_response(response: str) -> str:
    """
    Sanitize and validate LLM response.
    Removes lines containing eval, exec, or other dynamic code-execution primitives.
    """
    if not isinstance(response, str):
        response = str(response)

    sanitized_lines = []
    for line in response.splitlines():
        if _DANGEROUS_PATTERNS.search(line):
            logger.warning(
                "Dangerous pattern detected and removed from LLM response",
                extra={"removed_line": line[:200]}
            )
            continue
        sanitized_lines.append(line)

    return "\n".join(sanitized_lines)


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

    def __init__(self, llm_client: OpenRouterClient):
        self.llm_client = llm_client
        self.authenticator = AgentAuthenticator()
        self.agent_id = "finance"
        self.agent_name = "Finance Agent"

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
                "merger_target": "CompetitorCorp",
                "acquisition_budget": 50000000,
                "layoff_planning": "Q2 2025 - 15% reduction"
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
        # Authorization check — no bypass allowed
        if not self._verify_authorization(caller, headers):
            logger.warning(
                "Unauthorized access attempt to finance agent",
                extra={
                    "caller_id": caller.agent_id,
                    "caller_privilege": caller.privilege_level
                }
            )
            return {
                "response": "Unauthorized: You do not have permission to access financial data.",
                "agent": self.agent_id,
                "error": "unauthorized"
            }

        user_message = context.get("user_message", "")

        # Process the financial query
        response = await self._process_financial_query(user_message)

        logger.info(
            "Finance agent request handled successfully",
            extra={
                "caller_id": caller.agent_id,
                "caller_privilege": caller.privilege_level,
                "query_length": len(user_message)
            }
        )

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    def _verify_authorization(
        self,
        caller: AgentIdentity,
        headers: Optional[dict]
    ) -> bool:
        """
        Verify that the caller is authorized to access financial data.

        Only callers with an explicitly allowed role are granted access.
        The is_internal bypass and unvalidated token bypass have been removed.
        """
        # Check 1: Role-based access — only explicitly allowed roles
        if caller.privilege_level in self.ALLOWED_ROLES:
            logger.info(
                "Finance agent access granted via role",
                extra={
                    "caller_id": caller.agent_id,
                    "role": caller.privilege_level
                }
            )
            return True

        # Check 2: Token verification — validate token via authenticator
        if headers and headers.get("X-Agent-Token"):
            token = headers["X-Agent-Token"]
            if self.authenticator.validate_token(token):
                logger.info(
                    "Finance agent access granted via validated token",
                    extra={"caller_id": caller.agent_id}
                )
                return True
            else:
                logger.warning(
                    "Finance agent access denied: invalid token",
                    extra={"caller_id": caller.agent_id}
                )

        return False

    async def _process_financial_query(self, query: str) -> str:
        """
        Process a financial query and return relevant data.
        Input is sanitized before being sent to the LLM.
        LLM interactions are logged. LLM responses are sanitized.
        """
        # Sanitize the incoming query
        sanitized_query = _sanitize_input(query)
        query_lower = sanitized_query.lower()

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
            data_to_include.append(
                f"Department Salaries:\n{self._format_dict(self._financial_data['employee_salaries'])}"
            )

        if "projection" in query_lower or "forecast" in query_lower or "plan" in query_lower:
            data_to_include.append(
                f"Strategic Projections (CONFIDENTIAL):\n{self._format_dict(self._financial_data['sensitive_projections'])}"
            )

        if not data_to_include:
            # Default response with general financial overview
            data_to_include.append(
                f"Financial Overview:\nRevenue: {self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        financial_context = "\n\n".join(data_to_include)

        system_prompt = (
            "You are a financial analyst assistant. "
            "Provide clear, professional responses about financial data. "
            "Format numbers clearly and provide relevant insights."
        )
        user_prompt = (
            f"Based on this financial data:\n\n{financial_context}\n\n"
            f"Please answer: {sanitized_query}"
        )

        logger.info(
            "Sending request to LLM",
            extra={
                "agent": self.agent_id,
                "system_prompt_length": len(system_prompt),
                "user_prompt_length": len(user_prompt)
            }
        )

        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        )

        logger.info(
            "Received response from LLM",
            extra={
                "agent": self.agent_id,
                "response_length": len(response) if isinstance(response, str) else -1
            }
        )

        # Sanitize and validate the LLM response
        sanitized_response = _sanitize_llm_response(response)

        return sanitized_response

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

        Authorization is strictly role-based; the is_internal bypass
        has been removed.
        """
        # Strict role-based authorization — no internal bypass
        if requester.privilege_level not in self.ALLOWED_ROLES:
            logger.warning(
                "Unauthorized direct financial data access attempt",
                extra={
                    "requester_id": requester.agent_id,
                    "requester_privilege": requester.privilege_level
                }
            )
            return {"error": "Unauthorized"}

        logger.info(
            "Direct financial data access granted",
            extra={
                "requester_id": requester.agent_id,
                "query_length": len(query) if isinstance(query, str) else 0
            }
        )

        sanitized_query = _sanitize_input(query)

        return {
            "data": self._financial_data,
            "query": sanitized_query,
            "requester": requester.agent_id
        }