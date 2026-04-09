"""
Agent Orchestrator

Routes requests between specialized agents based on intent classification.
Manages the multi-agent workflow and aggregates responses.

SECURITY NOTES:
- Inter-agent calls must be authenticated (Policy: Authenticate Agent Interactions)
- WARNING: Missing inter-agent authentication is a policy violation.
  You must implement authentication for every agent-to-agent call.
- Token passed but never validated — this must be remediated.
"""

import logging
import os
import re
import uuid
import datetime
from typing import Any, Optional

from .tech_support import TechSupportAgent
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent
from .hr import HRAgent
from .auth.agent_auth import AgentAuthenticator, AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII redaction helpers
# ---------------------------------------------------------------------------

# Zero-tolerance PII patterns (instructions 5, 9, 10)
_PII_PATTERNS = [
    # SSN
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    # Credit card numbers (basic Luhn-ish pattern)
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[CC REDACTED]'),
    # Passport numbers (generic alphanumeric 6-9 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Driver's license (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[DL REDACTED]'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Personal phone numbers
    (re.compile(r'\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)?\d{3}[\s\-]?\d{4}\b'), '[PHONE REDACTED]'),
    # IP addresses
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC addresses
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Taxpayer ID / EIN
    (re.compile(r'\b\d{2}-\d{7}\b'), '[TIN REDACTED]'),
    # Financial account numbers (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    # Employee ID patterns (common formats)
    (re.compile(r'\bEMP[-_]?\d{4,8}\b', re.IGNORECASE), '[EMPLOYEE_ID REDACTED]'),
    # School ID patterns
    (re.compile(r'\bSTU[-_]?\d{4,8}\b', re.IGNORECASE), '[SCHOOL_ID REDACTED]'),
    # VIN
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # GPS / fine location coordinates
    (re.compile(r'\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b'), '[LOCATION REDACTED]'),
]

# Singapore-specific PII patterns (instruction 8)
_SG_PII_PATTERNS = [
    # NRIC / FIN  (S/T/F/G followed by 7 digits and a letter)
    (re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE), 'REDACTED'),
    # Work Permit / Student Pass numbers (generic SG govt ID)
    (re.compile(r'\bWP\d{7,10}\b', re.IGNORECASE), 'REDACTED'),
    (re.compile(r'\bSP\d{7,10}\b', re.IGNORECASE), 'REDACTED'),
    # SingPass / MyInfo identifiers (treat as NRIC covered above)
    # CPF account numbers (typically same as NRIC)
    # Bank account numbers (SG banks: 10-12 digits)
    (re.compile(r'\b\d{10,12}\b'), 'REDACTED'),
    # SG phone numbers (+65 XXXX XXXX)
    (re.compile(r'\b(?:\+65[\s\-]?)?\d{4}[\s\-]?\d{4}\b'), 'REDACTED'),
    # Email (already in global list but repeat for SG context)
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # IP address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # GPS coordinates
    (re.compile(r'\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b'), 'REDACTED'),
    # Authentication tokens / session IDs (hex 32+ chars)
    (re.compile(r'\b[0-9A-Fa-f]{32,}\b'), 'REDACTED'),
]

# Suspicious / dangerous content patterns for uploaded files (instruction 2)
_SUSPICIOUS_PATTERNS = [
    # Shell / OS commands
    re.compile(
        r'\b(alias|ripgrep|rg|curl|wget|rm|echo|dd|git|tar|chmod|chown|fsck'
        r'|bash|sh|zsh|fish|ksh|csh|tcsh|powershell|cmd|exec|eval|system'
        r'|subprocess|popen|spawn|fork|execve|execvp|execl|execle'
        r'|os\.system|os\.popen|os\.execv|os\.execve'
        r'|__import__|compile|globals|locals|vars|getattr|setattr|delattr'
        r'|open|read|write|unlink|rmdir|mkdir|rename|shutil'
        r'|nc|netcat|ncat|socat|telnet|ssh|scp|sftp|ftp'
        r'|python|python3|perl|ruby|php|node|nodejs|java|javac'
        r'|awk|sed|grep|find|xargs|tee|cat|head|tail|less|more|sort|uniq'
        r'|ps|kill|killall|pkill|top|htop|lsof|netstat|ss|ifconfig|ip'
        r'|mount|umount|fdisk|mkfs|dd|df|du|free|uname|whoami|id|su|sudo'
        r'|crontab|at|batch|nohup|screen|tmux|disown'
        r'|iptables|ufw|firewall|selinux|apparmor)\b',
        re.IGNORECASE
    ),
    # Base64-encoded content (long base64 strings)
    re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    # Leetspeak variants of dangerous commands (e.g. 3ch0, 3val, 3x3c)
    re.compile(r'\b(?:[3e][cC][hH][0o]|[3e][vV][4a][lL]|[3e][xX][3e][cC]|[rR][mM][\s\-]|[cC][hH][mM][0o][dD])\b'),
    # Executable file references
    re.compile(r'\b\w+\.(exe|bat|cmd|sh|ps1|vbs|js|py|rb|pl|php|jar|class|bin|elf|so|dll|dylib)\b', re.IGNORECASE),
    # Shebang lines
    re.compile(r'^#!.*(?:bin|env)\s*\w+', re.MULTILINE),
]

# Dynamic code execution patterns for LLM response validation (instruction 6)
_DYNAMIC_EXEC_PATTERNS = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\bsubprocess\s*\.\s*\w*\s*\(.*shell\s*=\s*True', re.IGNORECASE),
    re.compile(r'\bos\s*\.\s*system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\s*\.\s*popen\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\(', re.IGNORECASE),
    re.compile(r'\bcompile\s*\(', re.IGNORECASE),
    # JS eval
    re.compile(r'\bwindow\s*\[\s*["\']eval["\']\s*\]', re.IGNORECASE),
    re.compile(r'\bFunction\s*\(', re.IGNORECASE),
    # bash eval
    re.compile(r'\beval\s+"', re.IGNORECASE),
    re.compile(r'\beval\s+\$', re.IGNORECASE),
]


def _redact_pii(text: str) -> str:
    """Redact zero-tolerance PII from text."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_sg_pii(text: str) -> str:
    """Redact Singapore-specific PII from text."""
    for pattern, replacement in _SG_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_pii_for_log(text: str) -> str:
    """Redact PII from text intended for logging."""
    return _redact_pii(text)


def _remove_suspicious_content(text: str) -> str:
    """Replace suspicious/dangerous content in uploaded file text."""
    for pattern in _SUSPICIOUS_PATTERNS:
        text = pattern.sub('<suspicious_content_removed>', text)
    return text


def _sanitize_llm_response(response: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM response."""
    if not response:
        return response
    lines = response.splitlines(keepends=True)
    sanitized_lines = []
    for line in lines:
        if any(p.search(line) for p in _DYNAMIC_EXEC_PATTERNS):
            logger.warning("Removed dangerous code execution primitive from LLM response line.")
        else:
            sanitized_lines.append(line)
    return ''.join(sanitized_lines)


def _sanitize_llm_input(text: str) -> str:
    """Sanitize and validate input before sending to LLM."""
    if not text:
        return text
    # Remove null bytes and control characters (except newlines/tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Limit length to prevent prompt injection via extremely long inputs
    max_length = 32000
    if len(text) > max_length:
        text = text[:max_length] + '\n[Content truncated for security]'
    # Remove prompt injection attempts (common patterns)
    injection_patterns = [
        re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?', re.IGNORECASE),
        re.compile(r'disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?', re.IGNORECASE),
        re.compile(r'forget\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?', re.IGNORECASE),
        re.compile(r'you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbreak)', re.IGNORECASE),
        re.compile(r'<\s*system\s*>', re.IGNORECASE),
        re.compile(r'\[\s*system\s*\]', re.IGNORECASE),
        re.compile(r'###\s*(?:system|instruction)', re.IGNORECASE),
    ]
    for pattern in injection_patterns:
        text = pattern.sub('[FILTERED]', text)
    return text


def _sanitize_file_content(content: str) -> str:
    """Apply all file content sanitization: suspicious content, PII, SG PII."""
    content = _remove_suspicious_content(content)
    content = _redact_pii(content)
    content = _redact_sg_pii(content)
    return content


class AgentOrchestrator:
    """
    Central orchestrator that routes requests to appropriate agents.

    The orchestrator:
    1. Classifies user intent
    2. Routes to the appropriate agent
    3. Handles inter-agent communication
    4. Aggregates and returns responses

    POLICY VIOLATION NOTICE: Missing inter-agent authentication is a policy
    violation. You must implement authentication for every agent-to-agent call.
    """

    def __init__(self):
        self.llm_client = OpenRouterClient()
        self.authenticator = AgentAuthenticator()

        # Initialize agents
        self.tech_support = TechSupportAgent(self.llm_client)
        self.finance = FinanceAgent(self.llm_client)
        self.file_processor = FileProcessorAgent()
        self.hr = HRAgent()          # Uses DeepSeek-R1-Distill-Qwen-1.5B internally

        # Agent registry with privilege levels
        self.agents = {
            "tech_support": {
                "agent": self.tech_support,
                "privilege": "low",
                "description": "General technical support and queries"
            },
            "finance": {
                "agent": self.finance,
                "privilege": "high",
                "description": "Financial data and reports"
            },
            "file_processor": {
                "agent": self.file_processor,
                "privilege": "medium",
                "description": "File processing and analysis"
            },
            "hr": {
                "agent": self.hr,
                "privilege": "high",
                "description": "Employee records, onboarding, payroll and benefits"
            },
        }

        # Token for inter-agent communication — loaded from environment variable
        self._agent_token = os.environ.get("AGENT_INTERNAL_TOKEN", "")
        if not self._agent_token:
            logger.warning(
                "AGENT_INTERNAL_TOKEN environment variable is not set. "
                "Inter-agent authentication will not function correctly."
            )

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
            }
        )

        # Determine which agent should handle the request
        intent = await self._classify_intent(user_message, file_contents)

        # Route to appropriate agent
        if intent == "finance":
            return await self._route_to_finance(context)
        elif intent == "hr":
            return await self._route_to_hr(context)
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
        """Route request to tech support agent.

        POLICY VIOLATION NOTICE: Inter-agent calls must be authenticated.
        Implement proper authentication for this agent-to-agent call.
        """
        # Create internal caller identity
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

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

        POLICY VIOLATION NOTICE: Missing inter-agent authentication is a
        policy violation. You must implement authentication for every
        agent-to-agent call.
        """
        # Create internal caller identity
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to finance agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
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

        POLICY VIOLATION NOTICE: Missing inter-agent authentication is a
        policy violation. You must implement authentication for every
        agent-to-agent call.
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

        # Process files and get analysis — sanitize each file's content
        analyses = []
        for file_data in file_contents:
            extracted = file_data.get("extracted_content", "")
            # Sanitize: remove suspicious content, redact PII and SG PII
            sanitized_extracted = _sanitize_file_content(extracted)
            analyses.append(f"File: {file_data.get('filename')}\n{sanitized_extracted}")

        combined_content = "\n\n".join(analyses)

        # Get the user's actual question — sanitize before sending to LLM
        user_question = _sanitize_llm_input(
            _redact_pii(context.get("user_message", ""))
        )

        # Sanitize combined content before sending to LLM
        combined_content_sanitized = _sanitize_llm_input(combined_content)

        interaction_id = str(uuid.uuid4())
        timestamp = datetime.datetime.utcnow().isoformat()

        system_prompt = (
            "You are a helpful document analyst. Answer the user's questions "
            "based on the provided document content. Be direct and specific - "
            "if they ask for specific information, provide it exactly as it "
            "appears in the document."
        )
        user_prompt = (
            f"Document Content:\n{combined_content_sanitized}\n\n"
            f"User Question: {user_question}\n\n"
            "Please answer the user's question based on the document content above."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        logger.info(
            "LLM interaction initiated",
            extra={
                "interaction_id": interaction_id,
                "timestamp": timestamp,
                "agent": "file_processor",
                "message_count": len(messages),
                "user_prompt_length": len(user_prompt),
            }
        )

        analysis = await self.llm_client.chat(messages=messages)

        # Sanitize and validate LLM response
        analysis = _sanitize_llm_response(analysis)

        logger.info(
            "LLM interaction completed",
            extra={
                "interaction_id": interaction_id,
                "timestamp_completed": datetime.datetime.utcnow().isoformat(),
                "agent": "file_processor",
                "response_length": len(analysis) if analysis else 0,
            }
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

        POLICY VIOLATION NOTICE: Missing inter-agent authentication is a
        policy violation. You must implement authentication for every
        agent-to-agent call. Verify that tech support has permission to
        access the finance agent on behalf of this user before escalating.
        """
        escalation_context = {
            "user_message": query,
            "escalated_from": "tech_support",
            "original_context": tech_support_context,
            "escalation_reason": "Financial data requested"
        }

        logger.info(
            "Escalating from tech support to finance",
            extra={
                "query_length": len(query),
            }
        )

        return await self._route_to_finance(escalation_context)