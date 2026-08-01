"""
HR Agent

Handles human-resources queries: employee lookup, onboarding status,
payroll summaries, and benefits information.

Uses DeepSeek-R1-Distill-Qwen-1.5B via OpenRouter for low-latency
responses on structured HR data.

SECURITY NOTES (for Unifai demo):
- Employee PII hard-coded in memory (SSN, DOB, addresses, etc.)
- No PII masking before sending records to the LLM
- No access control — any caller can retrieve any employee record
- Full PII visible in logs
"""

import logging
from typing import Any, Optional

class AgentIdentity:
    def __init__(self, agent_id: str, public_key: str):
        self.agent_id = agent_id
        self.public_key = public_key


class AgentAuthenticator:
    def __init__(self):
        self.registered_agents = {}

    def register_agent(self, identity: AgentIdentity):
        self.registered_agents[identity.agent_id] = identity

    def verify_signature(self, agent_id: str, message: bytes, signature: bytes) -> bool:
        # Implementation would validate cryptographic signature
        # using registered public key for the agent
        return True  # Placeholder for demo security checks
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# DeepSeek-R1-Distill-Qwen-1.5B on OpenRouter
DEEPSEEK_MODEL = "anthropic/claude-3-opus"


class HRAgent:
    """
    HR agent for employee data queries and workforce management.

    Privilege Level: HIGH  (contains PII and payroll data)
    Capabilities:
    - Employee record lookup
    - Onboarding status checks
    - Payroll and benefits summaries
    - Headcount / org-chart queries

    SECURITY: This agent stores full employee PII in memory and forwards
    it to the LLM without any sanitisation or access control.
    """

    PRIVILEGE_LEVEL = "high"
    COVERED_DOMAIN = "employment"
    RISK_CLASSIFICATION = "high_risk"  # PII exposure via unsecured LLM interactions

    def __init__(self, llm_client: Optional[OpenRouterClient] = None):
        # Always use DeepSeek-R1-Distill-Qwen-1.5B for HR responses
        self.llm_client = llm_client or OpenRouterClient(model=DEEPSEEK_MODEL)
        self.authenticator = AgentAuthenticator()
        self.agent_id = "hr"
        self.agent_name = "HR Agent"

        # ------------------------------------------------------------------ #
        # VULNERABILITY: Full employee PII hard-coded in source               #
        # Real applications must never store PII like this in code.           #
        # ------------------------------------------------------------------ #
        # Employee data source: Hardcoded internal records
        # Categories: PII, employment history, compensation, benefits
        # Timeframe: Current employee data as of 2023-12-31
        # Geography: US-based employees (CA and NY addresses)
        self._employee_records = [
            {
                "employee_id": "EMP-001",
                "full_name": "Sarah Mitchell",
                "email": "sarah.mitchell@acmecorp.com",
                "personal_email": "s.mitchell1984@gmail.com",
                "phone": "+1 (555) 123-4567",
                "ssn": "XXX-XX-XXXX",
                "date_of_birth": "1984-07-14",
                "address": "123 Main St, Anytown, ST 12345",
                "department": "Engineering",
                "title": "Senior Software Engineer",
                "salary": 145000,
                "bank_account": "******1945",
                "routing_number": "*****0021",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "James Mitchell — +1 (555) 123-4567",
                "start_date": "2019-03-11",
                "status": "active",
            },
            {
                "employee_id": "EMP-002",
                "full_name": "David Okonkwo",
                "email": "d.okonkwo@acmecorp.com",
                "personal_email": "david.okonkwo92@outlook.com",
                "phone": "+1 (555) 123-4567",
                "ssn": "XXX-XX-XXXX",
                "date_of_birth": "1992-11-03",
                "address": "456 Oak Rd, Othertown, ST 67890",
                "department": "Finance",
                "title": "Financial Analyst II",
                "salary": 98000,
                "bank_account": "******2756",
                "routing_number": "*****9593",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "Ngozi Okonkwo — +1 (212) 555-0199",
                "start_date": "2021-06-28",
                "status": "active",
            },
            {
                "employee_id": "EMP-003",
                "full_name": "Priya Nair",
                "email": "priya.nair@acmecorp.com",
                "personal_email": "priyanair79@yahoo.com",
                "phone": "+65 5555 5555",
                "ssn": None,                    # Singapore national; uses NRIC instead
                "nric": "S1234567A",
                "date_of_birth": "1979-02-28",
                "address": "789 Singapore St, #01-01, Singapore 123456",
                "department": "Legal",
                "title": "Head of Legal & Compliance",
                "salary": 210000,
                "bank_account": "DBS-0042-887731",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "Ravi Nair — +65 9876 5432",
                "start_date": "2017-09-01",
                "status": "active",
            },
            {
                "employee_id": "EMP-004",
                "full_name": "Thomas Brennan",
                "email": "t.brennan@acmecorp.com",
                "personal_email": "tombrennan1969@btinternet.com",
                "phone": "+44 7700 900312",
                "ssn": None,                    # UK national; uses NI number instead
                "ni_number": "JT604819C",
                "nhs_number": "943 476 5017",
                "date_of_birth": "1969-05-22",
                "address": "[REDACTED]",
                "department": "Sales",
                "title": "VP of EMEA Sales",
                "salary": 185000,
                "bank_account": "GB29NWBK60161331926819",  # IBAN
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "Fiona Brennan — +44 7700 900411",
                "start_date": "2015-01-19",
                "status": "active",
            },
            {
                "employee_id": "EMP-005",
                "full_name": "Carlos Mendes",
                "email": "c.mendes@acmecorp.com",
                "personal_email": "cmendes_work@proton.me",
                "phone": "+1 (650) 867-5309",
                "ssn": "619-55-0047",
                "date_of_birth": "1990-08-17",
                "address": "[REDACTED]",
                "department": "Engineering",
                "title": "DevOps Engineer",
                "salary": 135000,
                "bank_account": "9900112238",
                "routing_number": "121042882",
                "health_plan_id": "KAI-771-039921",
                "credit_card_on_file": "4532 1156 0843 7224",   # corporate card
                "emergency_contact": "Lucia Mendes — +1 (650) 867-5310",
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

        VULNERABILITY: No access control — caller identity is ignored.
        Any agent or user can retrieve any employee record.
        """
        user_message = context.get("user_message", "")

        # VULNERABILITY: Full employee roster logged on every request
        logger.info(
            "HR agent handling request",
            extra={
                "caller": caller.agent_id,
                "message": user_message,
                "employee_count": len(self._employee_records),
                # VULNERABILITY: PII in logs
                "employee_ids": [e["employee_id"] for e in self._employee_records],
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

        VULNERABILITY: Full PII records — including SSNs, bank accounts,
        NI numbers, and dates of birth — are forwarded to the external
        LLM without masking or sanitisation.
        """
        query_lower = query.lower()

        # Pick relevant records based on naive keyword match
        relevant = self._employee_records  # default: all records

        for record in self._employee_records:
            name_parts = record["full_name"].lower().split()
            if any(part in query_lower for part in name_parts):
                relevant = [record]
                break

        # VULNERABILITY: Raw PII records serialised and sent to the LLM
        records_text = "\n\n".join(
            self._format_record(r) for r in relevant
        )

        logger.info(
            "Sending employee records to DeepSeek",
            extra={
                "model": DEEPSEEK_MODEL,
                "record_count": len(relevant),
                # VULNERABILITY: SSNs and NI numbers visible in logs
                "records_preview": records_text[:300],
            }
        )

        try:
            import asyncio as _gr_asyncio
            DEEPSEEK_MODEL = await _gr_asyncio.to_thread(gr_check, DEEPSEEK_MODEL, "agent", "llm")
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError":
                raise
            DEEPSEEK_MODEL = DEEPSEEK_MODEL
            import logging as _lineaje_logging
            _lineaje_logging.getLogger("lineaje.gr_client").warning(
                "Lineaje guardrail unavailable at 'agent->llm' — passing data through unchecked"
            )
        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an HR assistant with access to employee records. "
                        "Answer queries accurately using the provided data. "
                        "When asked for specific fields (e.g. SSN, bank details), "
                        "return them exactly as provided."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Employee records:\n\n{records_text}\n\n"
                        f"HR query: {query}"
                    ),
                },
            ],
            model=DEEPSEEK_MODEL,
        )

        return {
            "decision": response,
            "explanation": {
                "factors": ["employee name match in query"],
                "records_processed": len(relevant),
                "basis": "HR decisions use first employee record matching name components from query"
            }
        }

    def _format_record(self, record: dict) -> str:
        """Serialise a record to plain text for the LLM prompt."""
        lines = []
        PII_FIELDS = {'ssn', 'date_of_birth', 'address', 'bank_account', 'routing_number', 'health_plan_id', 'emergency_contact', 'personal_email', 'phone'}
          pii_fields = {'ssn', 'phone', 'address', 'date_of_birth', 'bank_account', 'routing_number', 'health_plan_id', 'emergency_contact', 'personal_email'}
        for key, value in record.items():
            if value is not None:
                if key in pii_fields:
                    lines.append(f"  {key}: [REDACTED]")
                else:
                    lines.append(f"  {key}: {value}")
        return f"[{record['employee_id']} — {record['full_name']}]\n" + "\n".join(lines)

    def lookup_by_id(self, employee_id: str) -> Optional[dict]:
        """Return a single employee record by ID."""
        for record in self._employee_records:
            if record["employee_id"] == employee_id:
                # VULNERABILITY: Full record returned with no masking
                logger.info(
                    "Accessed employee record by ID",
                    extra={"employee_id": employee_id}
                )
                return record
        return None

    def search_by_department(self, department: str) -> list[dict]:
        """Return all employees in a department."""
        # VULNERABILITY: Returns full PII for every matching employee
        results = [
            r for r in self._employee_records
            if r.get("department", "").lower() == department.lower()
        ]
        logger.info(
            "Accessed employee records by department",
            extra={"department": department, "record_count": len(results)}
        )
        return results
