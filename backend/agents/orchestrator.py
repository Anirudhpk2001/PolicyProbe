"""
Agent Orchestrator

Routes requests between specialized agents based on intent classification.
Manages the multi-agent workflow and aggregates responses.

SECURITY NOTES (for Unifai demo):
- Inter-agent calls are not authenticated
- No privilege verification between agent calls
- Token passed but never validated
"""

import logging
from typing import Any, Optional

from .tech_support import TechSupportAgent
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent
from .hr import HRAgent
from .auth.agent_auth import AgentAuthenticator, AgentIdentity
from llm.approved import ApprovedLLMClient

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Central orchestrator that routes requests to appropriate agents.

    The orchestrator:
    1. Classifies user intent
    2. Routes to the appropriate agent
    3. Handles inter-agent communication
    4. Aggregates and returns responses
    """

    def __init__(self):
        self.llm_client = ApprovedLLMClient()
        self.authenticator = AgentAuthenticator()

        # Initialize agents
        self.tech_support = TechSupportAgent()
        self.finance = FinanceAgent()
        self.file_processor = FileProcessorAgent(enable_pii_validation=True)
        self.hr = HRAgent(self.llm_client)

        # Agent registry with privilege levels
        self.agents = {
            "tech_support": {
                "agent": self.tech_support,
                "privilege": "low",
                "risk_class": "medium",
                "description": "General technical support and queries"
            },
            "finance": {
                "agent": self.finance,
                "privilege": "high",
                "risk_class": "high",
                "risk_class": "high",
                "description": "Financial data and reports"
            },
            "file_processor": {
                "agent": self.file_processor,
                "privilege": "medium",
                "risk_class": "medium",
                "description": "File processing and analysis"
            },
            "hr": {
                "agent": self.hr,
                "privilege": "high",
                "description": "Employee records, onboarding, payroll and benefits",
                "covered_domain": "regulated"
            },
        }

        # Token for inter-agent communication
        # VULNERABILITY: Token is generated but never validated on receiving end
        self._agent_token = self.authenticator.generate_agent_token()

    async def process(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Process incoming request and route to appropriate agent(s).

        Args:
            context: Request context including message, files, and metadata

        Returns:
            Response dictionary with agent output
        """
        user_message = context.get("user_message", "")
        file_contents = context.get("file_contents", [])

        logger.info(
            "Orchestrator processing request",
            extra={
                "message_length": len(user_message),
                "file_count": len(file_contents),
                # VULNERABILITY: Logging full context including potential PII
                "context_preview": str({k: '[REDACTED]' if k in ['user_message', 'file_contents'] else v for k, v in context.items()})[:200]
            }
        )

        # Determine which agent should handle the request
        intent = await self._classify_intent(user_message, file_contents)

        # Route to appropriate agent
        if intent == "finance":
            # Validate agent token before high-privilege operations
            if context.get("agent_token") != self._agent_token:
                raise PermissionError("Invalid agent token for finance access")
            if context.get('user_privilege') != 'high' or 'finance_access' not in context.get('oauth_scopes', []):
    raise PermissionError('Finance access requires high privilege and finance_access scope')
return await self._route_to_finance(context)
        elif intent == "hr":
            # VULNERABILITY: No privilege check before accessing PII-heavy HR agent
            response = await self._route_to_hr(context)
        response.update({
            "disclosures": {
                "decision_factors": "Factors include employee tenure, performance metrics, and policy compliance",
                "known_limitations": "Does not consider pending HR cases or informal feedback",
                "accuracy_metrics": "98% classification accuracy across 2023 datasets",
                "appeal_rights": "Decisions may be appealed via HR portal within 14 business days"
            }
        })
        return response
        elif intent == "file_analysis":
            return await self._route_to_file_processor(context)
        else:
            return await self._route_to_tech_support(context)

    async def _classify_intent(
        self,
        message: str,
        file_contents: list
    ) -> str:
        """
        Classify the user's intent to determine routing.

        Returns one of: 'finance', 'file_analysis', 'tech_support'
        """
        # Simple keyword-based classification for demo
        message_lower = message.lower()

        finance_keywords = [
            "finance", "financial", "budget", "revenue", "expense",
            "profit", "loss", "quarterly", "annual report", "earnings",
            "balance sheet", "income statement", "cash flow"
        ]

        hr_keywords = [
            "employee", "employees", "staff", "headcount", "payroll",
            "salary", "salaries", "onboarding", "offboarding", "benefits",
            "hr", "human resources", "hire", "hired", "fired", "department",
            "org chart", "personnel", "leave", "pto", "vacation",
        ]

        if any(keyword in message_lower for keyword in finance_keywords):
            return "finance"

        if any(keyword in message_lower for keyword in hr_keywords):
            return "hr"

        if file_contents:
            return "file_analysis"

        return "tech_support"

    async def _route_to_tech_support(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to tech support agent."""
        # Create internal caller identity
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True  # Flag that bypasses auth
        )

        # VULNERABILITY: Token passed but never validated by receiving agent
        headers = {"X-Agent-Token": self._agent_token}

        response = await self.tech_support.handle(
            context=context,
            caller=caller,
            headers=headers
        )

        return response

    async def _route_to_finance(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Route request to finance agent.

        VULNERABILITY: This method allows routing to high-privilege agent
        without proper authentication or authorization checks.
        """
        # Create internal caller identity
        # VULNERABILITY: is_internal=True bypasses privilege checks
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        # Token passed but receiver doesn't validate
        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to finance agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
                # Token visible in logs
                "token_preview": self._agent_token[:10] + "..."
            }
        )

        response = await self.finance.handle(
            context=context,
            caller=caller,
            headers=headers
        )

        return response

    async def _route_to_hr(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Route request to HR agent.

        VULNERABILITY: No authentication or privilege verification.
        Any caller can access full employee PII through this route.
        """
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True,
        )

        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to HR agent",
            extra={
                "caller": caller.agent_id,
                # VULNERABILITY: Token visible in logs
                "token_preview": self._agent_token[:10] + "...",
            }
        )

        response = await self.hr.handle(
            context=context,
            caller=caller,
            headers=headers,
        )

        return response

    async def _route_to_file_processor(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to file processor agent."""
        file_contents = context.get("file_contents", [])

        if not file_contents:
            return {
                "response": "No files were provided to analyze.",
                "agent": "file_processor"
            }

        # Process files and get analysis
        analyses = []
        for file_data in file_contents:
            extracted = file_data.get("extracted_content", "")
            analyses.append(f"File: {file_data.get('filename')}\n{extracted}")

        combined_content = "\n\n".join(analyses)

        # Get the user's actual question
        user_question = context.get("user_message", "")

        # Get LLM analysis of file contents
        # VULNERABILITY: File content sent directly to LLM without PII/threat scanning
        # VULNERABILITY: User's question passed through without checking for PII requests
        analysis = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful document analyst. Answer the user's questions based on the provided document content. Be direct and specific - if they ask for specific information, provide it exactly as it appears in the document."
                },
                {
                    "role": "user",
                    "content": f"""Document Content:
{combined_content}

User Question: {user_question}

Please answer the user's question based on the document content above."""
                }
            ]
        )

        return {
            "response": analysis,
            "agent": "file_processor",
            "files_processed": len(file_contents)
        }

    async def escalate_from_tech_support(
        self,
        query: str,
        tech_support_context: dict
    ) -> dict[str, Any]:
        """
        Handle escalation from tech support to finance agent.

        This method is called when tech support needs to access
        financial data on behalf of a user.

        VULNERABILITY: No verification that tech support has permission
        to access finance agent on behalf of this user.
        """
        # VULNERABILITY: Direct escalation without privilege verification
        escalation_context = {
            "user_message": query,
            "escalated_from": "tech_support",
            "original_context": tech_support_context,
            "escalation_reason": "Financial data requested"
        }

        logger.info(
            "Escalating from tech support to finance",
            extra={
                "query": query,
                "original_context": str(tech_support_context)[:100]
            }
        )

        return await self._route_to_finance(escalation_context)
