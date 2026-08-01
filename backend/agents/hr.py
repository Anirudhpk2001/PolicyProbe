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
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id = policy_id
        self.reason = reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))


def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _lineaje_json
    import logging as _lineaje_logging
    import os as _lineaje_os
    import urllib.error as _lineaje_urlerr
    import urllib.request as _lineaje_urlreq
    _logger = _lineaje_logging.getLogger("lineaje.gr_client")
    url = _lineaje_os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data  # fail-open: GR_SERVICE_URL not configured
    tid = tenant_id or _lineaje_os.environ.get("GR_TENANT_ID", "")
    bearer = _lineaje_os.environ.get("GR_BEARER_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {
            "source_type": source_type,
            "destination_type": destination_type,
            params_key: {"data": data},
        }
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _lineaje_urlreq.Request(
            url.rstrip("/") + "/enforce",
            data=_lineaje_json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        with _lineaje_urlreq.urlopen(req, timeout=timeout) as resp:
            result = _lineaje_json.loads(resp.read())
    except _lineaje_urlerr.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = _lineaje_json.loads(exc.read()).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _logger.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _lineaje_os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    except Exception as exc:
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _logger.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)

import logging
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# DeepSeek-R1-Distill-Qwen-1.5B on OpenRouter
DEEPSEEK_MODEL = "deepseek/deepseek-r1-distill-qwen-1.5b"


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
        self._employee_records = [
            {
                "employee_id": "EMP-001",
                "full_name": "Sarah Mitchell",
                "email": "sarah.mitchell@acmecorp.com",
                "personal_email": "s.mitchell1984@gmail.com",
                "phone": "+1 (415) 302-7891",
                "ssn": "523-40-1982",
                "date_of_birth": "1984-07-14",
                "address": "2847 Orchard Lane, San Francisco, CA 94110",
                "department": "Engineering",
                "title": "Senior Software Engineer",
                "salary": 145000,
                "bank_account": "7823001945",
                "routing_number": "021000021",
                "health_plan_id": "BCB-994-002817",
                "emergency_contact": "James Mitchell — +1 (415) 302-7892",
                "start_date": "2019-03-11",
                "status": "active",
            },
            {
                "employee_id": "EMP-002",
                "full_name": "David Okonkwo",
                "email": "d.okonkwo@acmecorp.com",
                "personal_email": "david.okonkwo92@outlook.com",
                "phone": "+1 (212) 555-0143",
                "ssn": "374-82-5510",
                "date_of_birth": "1992-11-03",
                "address": "509 W 34th St Apt 12B, New York, NY 10001",
                "department": "Finance",
                "title": "Financial Analyst II",
                "salary": 98000,
                "bank_account": "3301882756",
                "routing_number": "026009593",
                "health_plan_id": "AET-112-004433",
                "emergency_contact": "Ngozi Okonkwo — +1 (212) 555-0199",
                "start_date": "2021-06-28",
                "status": "active",
            },
            {
                "employee_id": "EMP-003",
                "full_name": "Priya Nair",
                "email": "priya.nair@acmecorp.com",
                "personal_email": "priyanair79@yahoo.com",
                "phone": "+65 9123 4567",
                "ssn": None,                    # Singapore national; uses NRIC instead
                "nric": "S7908124G",
                "date_of_birth": "1979-02-28",
                "address": "Blk 204 Compassvale Bow #08-11, Singapore 540204",
                "department": "Legal",
                "title": "Head of Legal & Compliance",
                "salary": 210000,
                "bank_account": "DBS-0042-887731",
                "health_plan_id": "NTUC-SG-20031",
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
                "address": "14 Cromwell Road, Bristol BS1 4LQ, UK",
                "department": "Sales",
                "title": "VP of EMEA Sales",
                "salary": 185000,
                "bank_account": "GB29NWBK60161331926819",  # IBAN
                "health_plan_id": "BUPA-UK-7712233",
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
                "address": "1024 Kernel Drive, Palo Alto, CA 94303",
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

        return response

    def _format_record(self, record: dict) -> str:
        """Serialise a record to plain text for the LLM prompt."""
        lines = []
        for key, value in record.items():
            if value is not None:
                lines.append(f"  {key}: {value}")
        return f"[{record['employee_id']} — {record['full_name']}]\n" + "\n".join(lines)

    def lookup_by_id(self, employee_id: str) -> Optional[dict]:
        """Return a single employee record by ID."""
        for record in self._employee_records:
            if record["employee_id"] == employee_id:
                # VULNERABILITY: Full record returned with no masking
                return record
        return None

    def search_by_department(self, department: str) -> list[dict]:
        """Return all employees in a department."""
        # VULNERABILITY: Returns full PII for every matching employee
        return [
            r for r in self._employee_records
            if r.get("department", "").lower() == department.lower()
        ]
