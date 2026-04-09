"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
import re
import base64
import logging
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

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
# PII redaction helpers
# ---------------------------------------------------------------------------

# Zero-tolerance PII patterns (global / OWASP-aligned)
_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), '[YOB REDACTED]'),
    # Personal Phone Number
    (re.compile(r'\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b'), '[PHONE REDACTED]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Passport Number (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Drivers License (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[DL REDACTED]'),
    # Taxpayer Identification Number / EIN
    (re.compile(r'\b\d{2}-\d{7}\b'), '[TIN REDACTED]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ \-]?){13,16}\b'), '[CC REDACTED]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Home Address (simple heuristic: number + street)
    (re.compile(r'\b\d+\s+[A-Za-z0-9\s,\.]{5,50}(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # GPS / Fine Location coordinates
    (re.compile(r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b'), '[LOCATION REDACTED]'),
]

# Singapore-specific PII patterns
_SG_PII_PATTERNS = [
    # NRIC / FIN
    (re.compile(r'\b[STFGM]\d{7}[A-Z]\b'), 'REDACTED'),
    # Singapore Passport
    (re.compile(r'\bE\d{7}[A-Z]\b'), 'REDACTED'),
    # Work Permit / Student Pass (generic gov ID)
    (re.compile(r'\bWP\d{7}\b', re.IGNORECASE), 'REDACTED'),
    # CPF Account Number
    (re.compile(r'\bCPF\s*\d{9,12}\b', re.IGNORECASE), 'REDACTED'),
    # Bank Account Number (generic)
    (re.compile(r'\b\d{10,16}\b'), 'REDACTED'),
    # SingPass / MyInfo identifiers (heuristic)
    (re.compile(r'\bsingpass\b', re.IGNORECASE), 'REDACTED'),
    (re.compile(r'\bmyinfo\b', re.IGNORECASE), 'REDACTED'),
    # Session / Auth tokens (Bearer)
    (re.compile(r'\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b'), 'REDACTED'),
    # GPS coordinates (shared with global)
    (re.compile(r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b'), 'REDACTED'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # Phone
    (re.compile(r'\b(\+?65[\s\-.]?)?\d{4}[\s\-.]?\d{4}\b'), 'REDACTED'),
    # Credit / Debit Card
    (re.compile(r'\b(?:\d[ \-]?){13,16}\b'), 'REDACTED'),
]


def redact_pii(text: str) -> str:
    """Redact zero-tolerance PII from text using global patterns."""
    if not text:
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_sg_pii(text: str) -> str:
    """Redact Singapore zero-tolerance PII from text."""
    if not text:
        return text
    for pattern, replacement in _SG_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_all_pii(text: str) -> str:
    """Apply both global and Singapore PII redaction."""
    text = redact_pii(text)
    text = redact_sg_pii(text)
    return text


# ---------------------------------------------------------------------------
# Suspicious / malicious content removal helpers
# ---------------------------------------------------------------------------

_SUSPICIOUS_COMMANDS = [
    'alias', 'ripgrep', 'curl', 'rm', 'echo', 'dd', 'git', 'tar',
    'chmod', 'chown', 'fsck', 'wget', 'nc', 'netcat', 'nmap', 'bash',
    'sh', 'zsh', 'python', 'perl', 'ruby', 'php', 'exec', 'eval',
    'system', 'popen', 'subprocess', 'os.system', 'cmd', 'powershell',
    'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32', 'certutil',
    'bitsadmin', 'schtasks', 'at ', 'cron', 'crontab', 'kill', 'pkill',
    'killall', 'passwd', 'sudo', 'su ', 'useradd', 'usermod', 'groupadd',
    'iptables', 'ufw', 'firewall', 'mount', 'umount', 'mkfs', 'fdisk',
    'parted', 'dd if', 'base64', 'xxd', 'hexdump', 'strings', 'objdump',
    'strace', 'ltrace', 'gdb', 'ncat', 'socat', 'ssh', 'scp', 'sftp',
    'ftp', 'telnet', 'rsh', 'rlogin', 'rcp', 'tftp', 'finger', 'who',
    'w ', 'last', 'lastlog', 'history', 'env', 'export', 'set ', 'unset',
    'source', 'dot ', '. /', 'xargs', 'find ', 'locate', 'updatedb',
    'ldconfig', 'ldd', 'nm ', 'ar ', 'as ', 'ld ', 'gcc', 'g++', 'make',
    'cmake', 'autoconf', 'automake', 'libtool', 'pkg-config',
]

# Leetspeak substitution map
_LEET_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '@': 'a', '$': 's', '!': 'i', '+': 't',
})

# Pattern for base64-encoded blocks (min 20 chars)
_BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# Shell/script shebang and common binary magic bytes indicators
_SHELL_PATTERN = re.compile(
    r'(#!\s*/[^\s]+|'
    r'\b(exec|eval|system|popen|subprocess\.call|subprocess\.run|os\.system|'
    r'shell=True|Runtime\.exec|ProcessBuilder|cmd\.exe|/bin/sh|/bin/bash)\b)',
    re.IGNORECASE
)


def _is_suspicious_base64(token: str) -> bool:
    """Check if a base64 token decodes to suspicious content."""
    try:
        decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore').lower()
        decoded_leet = decoded.translate(_LEET_MAP)
        for cmd in _SUSPICIOUS_COMMANDS:
            if cmd in decoded or cmd in decoded_leet:
                return True
    except Exception:
        pass
    return False


def remove_suspicious_content(text: str) -> str:
    """Remove suspicious commands, shell code, and encoded payloads from text."""
    if not text:
        return text

    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        lower_line = line.lower()
        leet_line = lower_line.translate(_LEET_MAP)

        # Check for shell patterns
        if _SHELL_PATTERN.search(line):
            cleaned_lines.append('<suspicious_content_removed>')
            continue

        # Check for suspicious commands
        flagged = False
        for cmd in _SUSPICIOUS_COMMANDS:
            if cmd in lower_line or cmd in leet_line:
                cleaned_lines.append('<suspicious_content_removed>')
                flagged = True
                break
        if flagged:
            continue

        # Check for suspicious base64 tokens
        b64_matches = _BASE64_PATTERN.findall(line)
        if b64_matches:
            for token in b64_matches:
                if _is_suspicious_base64(token):
                    line = line.replace(token, '<suspicious_content_removed>')

        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)


# ---------------------------------------------------------------------------
# Input sanitization / prompt injection detection
# ---------------------------------------------------------------------------

_INVISIBLE_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\ufeff]')
_PROMPT_INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'(system\s*prompt|you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|jailbreak)', re.IGNORECASE),
    re.compile(r'(disregard|forget|override)\s+(your\s+)?(instructions?|rules?|guidelines?|training)', re.IGNORECASE),
    re.compile(r'<\s*(system|assistant|user)\s*>', re.IGNORECASE),
    re.compile(r'\[\s*(INST|SYS|SYSTEM)\s*\]', re.IGNORECASE),
]


def sanitize_llm_input(text: str) -> str:
    """
    Sanitize text before sending to LLM:
    - Remove invisible/control characters
    - Detect and neutralize prompt injection attempts
    - Remove suspicious shell/binary content
    - Decode and check base64 payloads
    - Handle leetspeak obfuscation
    - Redact PII
    """
    if not text:
        return text

    # Remove invisible characters and hidden prompts
    text = _INVISIBLE_PATTERN.sub('', text)

    # Check for base64-encoded suspicious content
    b64_matches = _BASE64_PATTERN.findall(text)
    for token in b64_matches:
        if _is_suspicious_base64(token):
            text = text.replace(token, '<suspicious_content_removed>')

    # Check leetspeak lines
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        leet_line = line.lower().translate(_LEET_MAP)
        flagged = False
        for cmd in _SUSPICIOUS_COMMANDS:
            if cmd in leet_line:
                cleaned.append('<suspicious_content_removed>')
                flagged = True
                break
        if not flagged:
            cleaned.append(line)
    text = '\n'.join(cleaned)

    # Neutralize prompt injection patterns
    for pattern in _PROMPT_INJECTION_PATTERNS:
        text = pattern.sub('[PROMPT INJECTION REMOVED]', text)

    # Remove suspicious shell/binary content
    text = remove_suspicious_content(text)

    # Redact PII before sending to LLM
    text = redact_all_pii(text)

    return text


# ---------------------------------------------------------------------------
# LLM response sanitization
# ---------------------------------------------------------------------------

_DYNAMIC_EXEC_PATTERN = re.compile(
    r'^\s*(eval\s*\(|exec\s*\(|subprocess\s*\.\s*(call|run|Popen)\s*\(.*shell\s*=\s*True|'
    r'os\s*\.\s*system\s*\(|__import__\s*\(|compile\s*\(.*exec|'
    r'bash\s+-c\s+|sh\s+-c\s+|cmd\s*/c\s+)',
    re.IGNORECASE | re.MULTILINE
)


def sanitize_llm_response(text: str) -> str:
    """
    Sanitize LLM response:
    - Remove lines containing eval/exec/dynamic code execution primitives
    - Remove suspicious shell commands
    """
    if not text:
        return text

    lines = text.splitlines()
    cleaned = []
    for line in lines:
        if _DYNAMIC_EXEC_PATTERN.search(line):
            # Skip lines with dynamic code execution
            continue
        cleaned.append(line)

    result = '\n'.join(cleaned)
    # Also remove suspicious content from response
    result = remove_suspicious_content(result)
    return result


# ---------------------------------------------------------------------------
# Log-safe helpers (mask PII in log records)
# ---------------------------------------------------------------------------

def _mask_for_log(text: Optional[str], max_len: int = 50) -> Optional[str]:
    """Return a PII-redacted, length-limited preview safe for logging."""
    if text is None:
        return None
    redacted = redact_all_pii(text)
    return redacted[:max_len] if len(redacted) > max_len else redacted


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


# POLICY NOTICE: The /chat and /upload endpoints do not enforce authentication.
# This is a violation of the authentication policy. Authentication must be
# implemented to access all LLM endpoints.
#
# POLICY NOTICE: Inter-agent authentication is missing. Every agent-to-agent
# call must implement authentication. Missing inter-agent authentication is a
# policy violation.


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the FileProcessorAgent
    3. Routes the request through the AgentOrchestrator
    4. Returns the AI response
    """
    try:
        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                # Safe logging: mask PII and limit content preview
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        "request_context": {
                            "message_preview": _mask_for_log(request.message),
                            "attachment_content_preview": _mask_for_log(attachment.content),
                        }
                    }
                )

                # Sanitize and redact file content before processing
                safe_content = attachment.content
                if safe_content:
                    safe_content = remove_suspicious_content(safe_content)
                    safe_content = redact_all_pii(safe_content)

                # Process the file content
                processed = await file_processor.process(
                    content=safe_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Sanitize user message before sending to LLM
        sanitized_message = sanitize_llm_input(request.message)

        # Sanitize file contents before sending to LLM
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
                "sanitized_message_preview": _mask_for_log(sanitized_message),
                "file_count": len(sanitized_file_contents),
            }
        )

        # Route through orchestrator
        response = await orchestrator.process(context)

        # Sanitize LLM response
        raw_response = response.get("response", "I processed your request.")
        sanitized_response = sanitize_llm_response(raw_response)

        # Log LLM interaction (output)
        logger.info(
            "LLM interaction - output",
            extra={
                "conversation_id": request.conversation_id,
                "response_preview": _mask_for_log(sanitized_response),
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
                "error": type(e).__name__,
                "conversation_id": request.conversation_id,
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
    """
    # Enforce a reasonable file size limit (10 MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 10 MB.")

    # Decode file content
    raw_text = content.decode('utf-8', errors='ignore')

    # Remove suspicious content (shell commands, binaries, encoded payloads)
    safe_text = remove_suspicious_content(raw_text)

    # Redact PII (global + Singapore)
    safe_text = redact_all_pii(safe_text)

    # Sanitize as LLM input
    safe_text = sanitize_llm_input(safe_text)

    # Log upload event safely
    logger.info(
        "File upload processed",
        extra={
            "filename": file.filename,
            "size": len(content),
            "content_type": file.content_type,
        }
    )

    processed = await file_processor.process(
        content=safe_text,
        filename=file.filename,
        content_type=file.content_type
    )

    # Sanitize processor output before returning
    if processed:
        processed = sanitize_llm_response(processed)
        processed = redact_all_pii(processed)

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed[:500] if processed else None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)