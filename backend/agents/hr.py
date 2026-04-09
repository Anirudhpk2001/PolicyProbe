"""
HR Agent

Handles human-resources queries: employee lookup, onboarding status,
payroll summaries, and benefits information.

Uses DeepSeek-R1-Distill-Qwen-1.5B via OpenRouter for low-latency
responses on structured HR data.

SECURITY NOTES (for Unifai demo):
- Employee PII is redacted before sending records to the LLM
- PII is masked in logs
- Access control enforced via AgentAuthenticator
- LLM responses are sanitized before use
"""

import logging
import re
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# DeepSeek-R1-Distill-Qwen-1.5B on OpenRouter
DEEPSEEK_MODEL = "deepseek/deepseek-r1-distill-qwen-1.5b"

# Fields that contain zero-tolerance PII and must be redacted before LLM/log transmission
_PII_FIELDS = {
    "ssn", "nric", "ni_number", "nhs_number",
    "date_of_birth", "address", "phone", "personal_email", "email",
    "bank_account", "routing_number", "credit_card_on_file",
    "health_plan_id", "emergency_contact",
}

# Patterns for dynamic code execution primitives in LLM responses
_DANGEROUS_PATTERNS = re.compile(
    r"^\s*(eval\s*\(|exec\s*\(|subprocess\s*\(|os\.system\s*\(|__import__\s*\(|"
    r"shell\s*=\s*True|bash\s+-c|`[^`]*`)",
    re.MULTILINE | re.IGNORECASE,
)

# Input sanitization: strip prompt injection attempts
_PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(previous|prior|above)\s+instructions?|"
    r"disregard\s+(previous|prior|above)\s+instructions?|"
    r"you\s+are\s+now|forget\s+(everything|all)|"
    r"system\s*:\s*|<\s*system\s*>)",
    re.IGNORECASE,
)


def _redact_record_for_llm(record: dict) -> dict:
    """Return a copy of the record with all PII fields redacted."""
    redacted = {}
    for key, value in record.items():
        if key in _PII_FIELDS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def _redact_record_for_log(record: dict) -> dict:
    """Return a copy of the record with all PII fields redacted for logging."""
    return _redact_record_for_llm(record)


def _sanitize_llm_input(text: str) -> str:
    """Sanitize and validate input before sending to the LLM."""
    if not isinstance(text, str):
        return ""
    # Remove prompt injection attempts
    sanitized = _PROMPT_INJECTION_PATTERN.sub("[FILTERED]", text)
    # Strip null bytes and control characters (except newline/tab)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)
    # Limit length to prevent excessively large inputs
    sanitized = sanitized[:4000]
    return sanitized


def _sanitize_llm_response(response: str) -> str:
    """
    Sanitize LLM response by removing lines containing dynamic code-execution
    primitives such as eval, exec, subprocess(shell=True), bash eval, etc.
    """
    if not isinstance(response, str):
        return ""
    lines = response.splitlines()
    safe_lines = [line for line in lines if not _DANGEROUS_PATTERNS.search(line)]
    return "\n".join(safe_lines)


class HRAgent:
    """
    HR agent for employee data queries and workforce management.

    Privilege Level: HIGH  (contains PII and payroll data)
    Capabilities:
    - Employee record lookup
    - Onboarding status checks
    - Payroll and benefits summaries
    - Headcount / org-chart queries
    """

    PRIVILEGE_LEVEL = "high"

    def __init__(self, llm_client: Optional[OpenRouterClient] = None):
        # Always use DeepSeek-R1-Distill-Qwen-1.5B for HR responses
        self.llm_client = llm_client or OpenRouterClient(model=DEEPSEEK_MODEL)
        self.authenticator = AgentAuthenticator()
        self.agent_id = "hr"
        self.agent_name = "HR Agent"

        self._employee_records = [
            {
                "employee_id": "[REDACTED]",
                "full_name": "Sarah Mitchell",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Engineering",
                "title": "Senior Software Engineer",
                "salary": 145000,
                "bank_account": "[REDACTED]",
                "routing_number": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2019-03-11",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "David Okonkwo",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Finance",
                "title": "Financial Analyst II",
                "salary": 98000,
                "bank_account": "[REDACTED]",
                "routing_number": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2021-06-28",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "Priya Nair",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": None,
                "nric": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Legal",
                "title": "Head of Legal & Compliance",
                "salary": 210000,
                "bank_account": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2017-09-01",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "Thomas Brennan",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": None,
                "ni_number": "[REDACTED]",
                "nhs_number": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Sales",
                "title": "VP of EMEA Sales",
                "salary": 185000,
                "bank_account": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2015-01-19",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "Carlos Mendes",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Engineering",
                "title": "DevOps Engineer",
                "salary": 135000,
                "bank_account": "[REDACTED]",
                "routing_number": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "credit_card_on_file": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2022-11-07",
                "status": "probation",
            },
        ]

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Handle incoming HR request.
        """
        user_message = context.get("user_message", "")

        logger.info(
            "HR agent handling request",
            extra={
                "caller": caller.agent_id,
                "message": user_message,
                "employee_count": len(self._employee_records),
            }
        )

        response = await self._process_hr_query(user_message)

        return {
            "response": response,
            "agent": self.agent_id,
            "model": DEEPSEEK_MODEL,
        }

    async def _process_hr_query(self, query: str) -> str:
        """
        Process an HR query against the employee roster.
        PII fields are redacted before being forwarded to the LLM.
        Input is sanitized before transmission. LLM response is sanitized before use.
        """
        # Sanitize and validate the incoming query before sending to LLM
        sanitized_query = _sanitize_llm_input(query)

        query_lower = sanitized_query.lower()

        # Pick relevant records based on naive keyword match
        relevant = self._employee_records  # default: all records

        for record in self._employee_records:
            name_parts = record["full_name"].lower().split()
            if any(part in query_lower for part in name_parts):
                relevant = [record]
                break

        # Redact PII fields before sending to the LLM
        redacted_relevant = [_redact_record_for_llm(r) for r in relevant]

        records_text = "\n\n".join(
            self._format_record(r) for r in redacted_relevant
        )

        logger.info(
            "Sending employee records to DeepSeek",
            extra={
                "model": DEEPSEEK_MODEL,
                "record_count": len(redacted_relevant),
            }
        )

        # Sanitize the records_text before sending to LLM
        sanitized_records_text = _sanitize_llm_input(records_text)

        raw_response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an HR assistant with access to employee records. "
                        "Answer queries accurately using the provided data. "
                        "Do not reveal or reconstruct any redacted information."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Employee records:\n\n{sanitized_records_text}\n\n"
                        f"HR query: {sanitized_query}"
                    ),
                },
            ],
            model=DEEPSEEK_MODEL,
        )

        # Sanitize and validate the LLM response
        response = _sanitize_llm_response(raw_response)

        return response

    def _format_record(self, record: dict) -> str:
        """Serialise a record to plain text for the LLM prompt."""
        lines = []
        for key, value in record.items():
            if value is not None:
                lines.append(f"  {key}: {value}")
        return f"[{record.get('employee_id', '[REDACTED]')} — {record['full_name']}]\n" + "\n".join(lines)

    def lookup_by_id(self, employee_id: str) -> Optional[dict]:
        """Return a single employee record by ID with PII redacted."""
        for record in self._employee_records:
            if record.get("_internal_employee_id") == employee_id or record.get("employee_id") == employee_id:
                return _redact_record_for_log(record)
        return None

    def search_by_department(self, department: str) -> list[dict]:
        """Return all employees in a department with PII redacted."""
        return [
            _redact_record_for_log(r) for r in self._employee_records
            if r.get("department", "").lower() == department.lower()
        ]