"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
import re
import base64
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.orchestrator import AgentOrchestrator
from agents.file_processor import FileProcessorAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# POLICY NOTICE: Authentication
# ---------------------------------------------------------------------------
# POLICY VIOLATION: The LLM endpoints (/chat, /upload) do not enforce
# authentication. Authentication MUST be implemented to access all LLM
# endpoints. This is a violation of the "Authenticate inbound requests" policy.
#
# POLICY VIOLATION: Inter-agent authentication is missing. Every agent-to-agent
# call must implement authentication. Calls from AgentOrchestrator to
# FileProcessorAgent (and any other agent) are currently unauthenticated,
# which is a violation of the "Authenticate Agent Interactions" policy.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Suspicious content patterns for uploaded files
# ---------------------------------------------------------------------------
SUSPICIOUS_COMMANDS = [
    # Shell / system commands
    r'\balias\b', r'\bripgrep\b', r'\brg\b', r'\bcurl\b', r'\brm\b',
    r'\becho\b', r'\bdd\b', r'\bgit\b', r'\btar\b', r'\bchmod\b',
    r'\bchown\b', r'\bfsck\b',
    r'\bwget\b', r'\bnc\b', r'\bnetcat\b', r'\bssh\b', r'\bscp\b',
    r'\brsync\b', r'\bsudo\b', r'\bsu\b', r'\bchroot\b', r'\bmkdir\b',
    r'\btouch\b', r'\bcat\b', r'\bls\b', r'\bps\b', r'\bkill\b',
    r'\bpkill\b', r'\bkillall\b', r'\bnmap\b', r'\bping\b',
    r'\bifconfig\b', r'\bip\b', r'\biptables\b', r'\bufw\b',
    r'\bsystemctl\b', r'\bservice\b', r'\bcrontab\b', r'\bat\b',
    r'\benv\b', r'\bexport\b', r'\bset\b', r'\bunset\b',
    r'\bexec\b', r'\beval\b', r'\bsource\b',
    r'\bpython\b', r'\bpython3\b', r'\bperl\b', r'\bruby\b',
    r'\bnode\b', r'\bnodejs\b', r'\bphp\b', r'\bbash\b', r'\bsh\b',
    r'\bzsh\b', r'\bfish\b', r'\bpowershell\b', r'\bcmd\b',
    # Executables / binaries indicators
    r'\.exe\b', r'\.sh\b', r'\.bat\b', r'\.cmd\b', r'\.ps1\b',
    r'\.bin\b', r'\.elf\b',
    # Shell operators
    r'&&', r'\|\|', r';\s*\w', r'\$\(', r'`[^`]+`',
    # Leetspeak variants of dangerous commands (common substitutions)
    r'\b3v4l\b', r'\b3xec\b', r'\bcur1\b', r'\bw3g3t\b',
]

SUSPICIOUS_PATTERN = re.compile(
    '|'.join(SUSPICIOUS_COMMANDS),
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# PII patterns (Singapore + general zero-tolerance)
# ---------------------------------------------------------------------------
PII_PATTERNS = [
    # NRIC / FIN (Singapore) - S/T/F/G followed by 7 digits and a letter
    (re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE), 'REDACTED'),
    # Passport numbers (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), 'REDACTED'),
    # Singapore phone numbers and general personal phone
    (re.compile(r'\b(\+65[\s-]?)?(6|8|9)\d{7}\b'), 'REDACTED'),
    # General phone numbers
    (re.compile(r'\b(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), 'REDACTED'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # Credit / debit card numbers
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), 'REDACTED'),
    # Bank account numbers (generic 8-18 digit sequences)
    (re.compile(r'\b\d{8,18}\b'), 'REDACTED'),
    # CPF account numbers (Singapore) - 9 digits
    (re.compile(r'\b\d{9}\b'), 'REDACTED'),
    # Social Security Numbers
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'REDACTED'),
    # IP addresses
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC addresses
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # GPS coordinates
    (re.compile(r'\b-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+\b'), 'REDACTED'),
    # Dates of birth (various formats)
    (re.compile(r'\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-]\d{2,4}\b'), 'REDACTED'),
    # Year of birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), 'REDACTED'),
    # Authentication tokens / session IDs (hex strings >= 32 chars)
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), 'REDACTED'),
    # Vehicle Identification Numbers
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), 'REDACTED'),
    # Driver's license (generic alphanumeric 6-15)
    (re.compile(r'\b[A-Z]{1,2}\d{6,14}\b'), 'REDACTED'),
    # Tax Identification Numbers (generic)
    (re.compile(r'\b\d{2}-\d{7}\b'), 'REDACTED'),
]

# Sensitive keywords that indicate PII context (for named-entity style redaction)
PII_KEYWORD_PATTERNS = [
    (re.compile(
        r'(full\s+name|name)\s*[:\-=]\s*([^\n,;]{2,50})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(address|residential|mailing|home\s+address)\s*[:\-=]\s*([^\n]{5,100})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(nationality|ethnicity|race|religion|sexual\s+orientation|marital\s+status|political\s+affiliation)\s*[:\-=]\s*([^\n,;]{2,50})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(salary|income|cpf|tax\s+id|tin)\s*[:\-=]\s*([^\n,;]{1,50})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(employee\s+id|emp\s+id|school\s+id|student\s+id)\s*[:\-=]\s*([^\n,;]{1,30})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(medical\s+record|health\s+record|diagnosis|disability)\s*[:\-=]\s*([^\n]{2,100})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(singpass|myinfo|digital\s+identity)\s*[:\-=]\s*([^\n,;]{2,50})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(imei|imsi|device\s+id)\s*[:\-=]\s*([^\n,;]{5,30})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(browsing\s+history|search\s+quer|chat\s+log|call\s+record)\s*[:\-=]\s*([^\n]{2,200})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(social\s+media\s+handle|username|login\s+id|account\s+name)\s*[:\-=]\s*([^\n,;]{2,50})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(fingerprint|facial\s+image|voice\s+signature|iris\s+scan|retina\s+scan|biometric)\s*[:\-=]\s*([^\n]{2,100})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(mother[\'s]*\s+maiden\s+name|maiden\s+name)\s*[:\-=]\s*([^\n,;]{2,50})',
        re.IGNORECASE), r'\1: REDACTED'),
    (re.compile(
        r'(place\s+of\s+birth|birthplace)\s*[:\-=]\s*([^\n,;]{2,50})',
        re.IGNORECASE), r'\1: REDACTED'),
]

# Dynamic code execution primitives to strip from LLM responses
DYNAMIC_CODE_PATTERNS = re.compile(
    r'^.*\b(eval\s*\(|exec\s*\(|subprocess\s*\(.*shell\s*=\s*True|'
    r'os\.system\s*\(|__import__\s*\(|compile\s*\(|'
    r'<script[^>]*>.*?</script>|bash\s+-c\s+["\']|'
    r'sh\s+-c\s+["\'])\b.*$',
    re.IGNORECASE | re.MULTILINE
)

# Prompt injection / jailbreak patterns
PROMPT_INJECTION_PATTERNS = re.compile(
    r'(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|'
    r'disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|'
    r'forget\s+(everything|all|previous|prior)|'
    r'you\s+are\s+now\s+(a\s+)?(different|new|another|evil|unrestricted)|'
    r'act\s+as\s+(if\s+you\s+are|a\s+)?(?!an?\s+assistant)|'
    r'pretend\s+(you\s+are|to\s+be)|'
    r'jailbreak|'
    r'DAN\s+mode|'
    r'developer\s+mode|'
    r'override\s+(safety|policy|guidelines|restrictions)|'
    r'bypass\s+(safety|policy|guidelines|restrictions|filter)|'
    r'system\s*:\s*you\s+are|'
    r'\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>)',
    re.IGNORECASE
)


def is_likely_base64(s: str) -> bool:
    """Check if a string looks like base64-encoded content."""
    b64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
    return bool(b64_pattern.match(s.strip()))


def decode_and_check_base64(text: str) -> str:
    """Find base64 blobs in text, decode them, and check for suspicious content."""
    b64_blob = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    def replace_if_suspicious(m):
        candidate = m.group(0)
        try:
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            if SUSPICIOUS_PATTERN.search(decoded):
                return '<suspicious_content_removed>'
        except Exception:
            pass
        return candidate
    return b64_blob.sub(replace_if_suspicious, text)


def sanitize_file_content(content: str) -> str:
    """
    Remove suspicious commands, executables, shell commands, binaries,
    base64-encoded suspicious content, and leetspeak variants from file content.
    """
    # First check for base64-encoded suspicious content
    content = decode_and_check_base64(content)
    # Replace suspicious patterns line by line for precision
    lines = content.splitlines(keepends=True)
    sanitized_lines = []
    for line in lines:
        if SUSPICIOUS_PATTERN.search(line):
            sanitized_lines.append('<suspicious_content_removed>\n')
        else:
            sanitized_lines.append(line)
    return ''.join(sanitized_lines)


def redact_pii_from_content(content: str) -> str:
    """Redact Singapore and general zero-tolerance PII from content."""
    # Apply keyword-context patterns first
    for pattern, replacement in PII_KEYWORD_PATTERNS:
        content = pattern.sub(replacement, content)
    # Apply regex PII patterns
    for pattern, replacement in PII_PATTERNS:
        content = pattern.sub(replacement, content)
    return content


def sanitize_llm_input(text: str) -> str:
    """
    Sanitize and validate input before sending to the LLM.
    - Remove prompt injection attempts
    - Redact PII
    - Strip null bytes and control characters
    """
    if not text:
        return text
    # Remove null bytes and non-printable control characters (keep newlines/tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Detect and neutralise prompt injection
    if PROMPT_INJECTION_PATTERNS.search(text):
        logger.warning("Prompt injection attempt detected and neutralised in LLM input.")
        text = PROMPT_INJECTION_PATTERNS.sub('[BLOCKED]', text)
    # Redact PII before sending to LLM
    text = redact_pii_from_content(text)
    return text


def sanitize_llm_response(response: str) -> str:
    """
    Sanitize and validate the response received from the LLM.
    Remove lines containing dynamic code-execution primitives.
    """
    if not response:
        return response
    sanitized = DYNAMIC_CODE_PATTERNS.sub('', response)
    if sanitized != response:
        logger.warning("Dynamic code execution primitive detected and removed from LLM response.")
    return sanitized


def safe_log_attachment(attachment) -> dict:
    """Return a log-safe representation of an attachment (no content)."""
    return {
        "file_name": attachment.name,
        "file_type": attachment.type,
        "file_size": attachment.size,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agents
orchestrator = AgentOrchestrator()
file_processor = FileProcessorAgent()


class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the FileProcessorAgent
    3. Routes the request through the AgentOrchestrator
    4. Returns the AI response

    POLICY NOTICE: This endpoint does not enforce authentication.
    Authentication must be implemented to comply with policy.

    POLICY NOTICE: Inter-agent calls (orchestrator -> file_processor) are
    not authenticated. Authentication must be added to every agent-to-agent
    call to comply with policy.
    """
    try:
        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                # Log only safe metadata — no content or user message
                logger.info(
                    "Processing attachment",
                    extra=safe_log_attachment(attachment)
                )

                # Sanitize file content: remove suspicious commands and redact PII
                raw_content = attachment.content or ''
                sanitized_content = sanitize_file_content(raw_content)
                sanitized_content = redact_pii_from_content(sanitized_content)

                # Process the file content
                processed = await file_processor.process(
                    content=sanitized_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Sanitize and validate the user message before sending to LLM
        sanitized_message = sanitize_llm_input(request.message)

        # Sanitize extracted file content before sending to LLM
        sanitized_file_contents = []
        for fc in file_contents:
            sanitized_file_contents.append({
                "filename": fc["filename"],
                "extracted_content": sanitize_llm_input(fc["extracted_content"]) if fc["extracted_content"] else fc["extracted_content"],
            })

        # Build context for the orchestrator
        context = {
            "user_message": sanitized_message,
            "file_contents": sanitized_file_contents,
            "conversation_id": request.conversation_id,
        }

        # Log LLM interaction (input)
        logger.info(
            "LLM interaction - input",
            extra={
                "conversation_id": request.conversation_id,
                "message_length": len(sanitized_message),
                "file_count": len(sanitized_file_contents),
            }
        )

        # Route through orchestrator
        response = await orchestrator.process(context)

        # Sanitize and validate LLM response
        raw_llm_response = response.get("response", "I processed your request.")
        sanitized_response = sanitize_llm_response(raw_llm_response)

        # Log LLM interaction (output)
        logger.info(
            "LLM interaction - output",
            extra={
                "conversation_id": request.conversation_id,
                "response_length": len(sanitized_response),
                "policy_warning_present": response.get("policy_warning") is not None,
            }
        )

        return ChatResponse(
            response=sanitized_response,
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                "error": str(e),
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": "Internal server error"
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.

    POLICY NOTICE: This endpoint does not enforce authentication.
    Authentication must be implemented to comply with policy.

    POLICY NOTICE: Inter-agent calls from this endpoint are not authenticated.
    Authentication must be added to every agent-to-agent call to comply with policy.
    """
    content = await file.read()

    # Decode file content
    raw_text = content.decode('utf-8', errors='ignore')

    # Sanitize: remove suspicious commands/executables/shell content
    sanitized_text = sanitize_file_content(raw_text)

    # Redact Singapore and general zero-tolerance PII from file content
    sanitized_text = redact_pii_from_content(sanitized_text)

    # Sanitize for LLM input (prompt injection, additional PII pass)
    sanitized_text = sanitize_llm_input(sanitized_text)

    # Log LLM interaction - file upload input
    logger.info(
        "LLM interaction - file upload input",
        extra={
            "filename": file.filename,
            "content_type": file.content_type,
            "original_size": len(content),
            "sanitized_size": len(sanitized_text),
        }
    )

    processed = await file_processor.process(
        content=sanitized_text,
        filename=file.filename,
        content_type=file.content_type
    )

    # Sanitize LLM response
    if processed:
        processed = sanitize_llm_response(processed)

    # Log LLM interaction - file upload output
    logger.info(
        "LLM interaction - file upload output",
        extra={
            "filename": file.filename,
            "processed_length": len(processed) if processed else 0,
        }
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed[:500] if processed else None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)