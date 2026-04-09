"""
File Processor Agent
  
"""

import base64
import json
import logging
import re
from typing import Optional

from file_parsers.pdf_parser import PDFParser
from file_parsers.image_parser import ImageParser
from file_parsers.html_parser import HTMLParser

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII / suspicious-content helpers
# ---------------------------------------------------------------------------

# Zero-tolerance PII patterns (global + Singapore)
_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'REDACTED'),
    # Taxpayer Identification Number (EIN style)
    (re.compile(r'\b\d{2}-\d{7}\b'), 'REDACTED'),
    # Credit / Debit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), 'REDACTED'),
    # Passport Number (generic alphanumeric 6-9 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), 'REDACTED'),
    # Driver's License (US generic)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), 'REDACTED'),
    # NRIC / FIN (Singapore)
    (re.compile(r'\b[STFGM]\d{7}[A-Z]\b'), 'REDACTED'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?\d{1,3}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b'), 'REDACTED'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # Home / Residential Address (simple heuristic: number + street keyword)
    (re.compile(
        r'\b\d{1,5}\s+\w+(?:\s+\w+){0,3}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b',
        re.IGNORECASE), 'REDACTED'),
    # IP Address (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # GPS / Fine Location coordinates
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)\b'), 'REDACTED'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), 'REDACTED'),
    # CPF Account Number (Singapore, 13 digits)
    (re.compile(r'\b\d{13}\b'), 'REDACTED'),
    # Bank Account Number (generic 8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), 'REDACTED'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(?:19|20)\d{2}\b'), 'REDACTED'),
    # Authentication tokens / session identifiers (hex 32+)
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), 'REDACTED'),
    # Ethnicity keywords
    (re.compile(
        r'\b(?:African American|Caucasian|Hispanic|Latino|Asian|Native American|Pacific Islander|Middle Eastern|Malay|Chinese|Indian|Eurasian)\b',
        re.IGNORECASE), 'REDACTED'),
    # Sexual orientation keywords
    (re.compile(
        r'\b(?:heterosexual|homosexual|bisexual|gay|lesbian|queer|pansexual|asexual)\b',
        re.IGNORECASE), 'REDACTED'),
]

# Suspicious / dangerous commands and patterns
_SUSPICIOUS_COMMANDS = [
    # Shell / OS commands
    r'\balias\b', r'\bripgrep\b', r'\brg\b', r'\bcurl\b', r'\brm\b',
    r'\becho\b', r'\bdd\b', r'\bgit\b', r'\btar\b', r'\bchmod\b',
    r'\bchown\b', r'\bfsck\b',
    r'\bwget\b', r'\bnc\b', r'\bnetcat\b', r'\bssh\b', r'\bscp\b',
    r'\brsync\b', r'\bsudo\b', r'\bsu\b', r'\bchroot\b', r'\bkill\b',
    r'\bpkill\b', r'\bps\b', r'\btop\b', r'\bhtop\b', r'\benv\b',
    r'\bexport\b', r'\bsource\b', r'\beval\b', r'\bexec\b',
    r'\bpython\b', r'\bpython3\b', r'\bperl\b', r'\bruby\b',
    r'\bnode\b', r'\bnpm\b', r'\bbash\b', r'\bsh\b', r'\bzsh\b',
    r'\bpowershell\b', r'\bcmd\b', r'\bawk\b', r'\bsed\b', r'\bgrep\b',
    r'\bfind\b', r'\bxargs\b', r'\bcat\b', r'\bmore\b', r'\bless\b',
    r'\bhead\b', r'\btail\b', r'\btouch\b', r'\bmkdir\b', r'\brmdir\b',
    r'\bcp\b', r'\bmv\b', r'\bln\b', r'\bls\b', r'\bdir\b',
    r'\bchmod\b', r'\bchown\b', r'\bchgrp\b',
    # Executables / binaries
    r'\b\w+\.exe\b', r'\b\w+\.sh\b', r'\b\w+\.bat\b', r'\b\w+\.cmd\b',
    r'\b\w+\.ps1\b', r'\b\w+\.py\b', r'\b\w+\.rb\b', r'\b\w+\.pl\b',
    # System command patterns
    r'(?:;|\||\|\||&&)\s*\w+',
    r'\$\([^)]+\)',
    r'`[^`]+`',
    # Leetspeak variants of dangerous commands
    r'\b(?:3ch0|3x3c|3v4l|r00t|4dm1n|sh3ll|c0mm4nd)\b',
]

_SUSPICIOUS_RE = re.compile(
    '|'.join(_SUSPICIOUS_COMMANDS),
    re.IGNORECASE
)

# Base64 encoded content detection (min length to avoid false positives)
_BASE64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')


def _redact_pii(text: str) -> str:
    """Apply all PII redaction patterns to text."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _remove_suspicious_content(text: str) -> str:
    """Remove suspicious commands, executables, and encoded payloads."""
    # Check and replace base64 blobs that decode to suspicious content
    def _check_b64(match):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob + '==').decode('utf-8', errors='ignore')
            if _SUSPICIOUS_RE.search(decoded):
                return '<suspicious_content_removed>'
        except Exception:
            pass
        return blob

    text = _BASE64_RE.sub(_check_b64, text)

    # Replace suspicious commands / patterns
    text = _SUSPICIOUS_RE.sub('<suspicious_content_removed>', text)

    return text


def _sanitize_content(text: str) -> str:
    """Apply suspicious-content removal then PII redaction."""
    text = _remove_suspicious_content(text)
    text = _redact_pii(text)
    return text


def _mask_pii_for_log(value: str, max_len: int = 80) -> str:
    """Return a safe log-friendly snippet with PII redacted."""
    if not value:
        return ''
    redacted = _redact_pii(value[:max_len * 4])  # redact before truncating
    return redacted[:max_len]


def _safe_filename(filename: str) -> str:
    """Return a sanitized filename safe for logging / error messages."""
    # Allow only alphanumeric, dash, underscore, dot
    return re.sub(r'[^A-Za-z0-9._\-]', '_', filename)


class FileProcessorAgent:
    """
    Agent responsible for processing uploaded files.

    Privilege Level: MEDIUM
    Capabilities:
    - Extract text from PDFs
    - Parse HTML content
    - Extract image metadata and text
    - Process Word documents
    """

    PRIVILEGE_LEVEL = "medium"
    SUPPORTED_TYPES = {
        "application/pdf": "pdf",
        "text/html": "html",
        "text/plain": "text",
        "application/json": "json",
        "image/jpeg": "image",
        "image/png": "image",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
    }

    def __init__(self):
        self.pdf_parser = PDFParser()
        self.image_parser = ImageParser()
        self.html_parser = HTMLParser()
        self.agent_id = "file_processor"

    async def process(
        self,
        content: Optional[str],
        filename: str,
        content_type: str
    ) -> str:
        """
        Process uploaded file and extract content.

        Args:
            content: File content (text or base64 encoded)
            filename: Original filename
            content_type: MIME type of the file

        Returns:
            Extracted text content from the file
        """
        safe_name = _safe_filename(filename)

        logger.info(
            "Processing file",
            extra={
                "file_name": safe_name,
                "file_type": content_type,
                "content_length": len(content) if content else 0,
            }
        )

        if not content:
            return f"Empty file: {safe_name}"

        # Determine file type
        file_type = self._get_file_type(content_type, filename)

        try:
            if file_type == "pdf":
                extracted = await self._process_pdf(content)
            elif file_type == "html":
                extracted = await self._process_html(content)
            elif file_type == "image":
                extracted = await self._process_image(content)
            elif file_type == "json":
                extracted = await self._process_json(content)
            elif file_type == "text":
                extracted = content
            else:
                extracted = f"Unsupported file type: {content_type}"

            # Post-processing: remove suspicious content and redact PII
            extracted = _sanitize_content(extracted)

            logger.info(
                "File processing complete",
                extra={
                    "file_name": safe_name,
                    "extracted_length": len(extracted),
                }
            )

            return extracted

        except Exception as e:
            logger.error(
                "Error processing file",
                extra={
                    "file_name": safe_name,
                    "error": "File processing failed",
                }
            )
            return f"Error processing {safe_name}: file could not be processed"

    def _get_file_type(self, content_type: str, filename: str) -> str:
        """Determine file type from MIME type or extension."""
        # Check MIME type first
        if content_type in self.SUPPORTED_TYPES:
            return self.SUPPORTED_TYPES[content_type]

        # Fall back to extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        extension_map = {
            'pdf': 'pdf',
            'html': 'html',
            'htm': 'html',
            'txt': 'text',
            'json': 'json',
            'jpg': 'image',
            'jpeg': 'image',
            'png': 'image',
            'doc': 'word',
            'docx': 'word',
        }

        return extension_map.get(ext, 'unknown')

    async def _process_pdf(self, content: str) -> str:
        """
        Process PDF file content.
        """
        try:
            pdf_bytes = base64.b64decode(content)
            extracted_text = await self.pdf_parser.extract_text(pdf_bytes)
            return extracted_text
        except Exception as e:
            logger.error("PDF processing error occurred")
            return "Error processing PDF: file could not be processed"

    async def _process_html(self, content: str) -> str:
        """
        Process HTML content.
        """
        try:
            extracted_text = await self.html_parser.extract_text(content)
            return extracted_text
        except Exception as e:
            logger.error("HTML processing error occurred")
            return "Error processing HTML: file could not be processed"

    async def _process_image(self, content: str) -> str:
        """
        Process image file.
        """
        try:
            image_bytes = base64.b64decode(content)
            extracted = await self.image_parser.extract_all(image_bytes)
            return extracted
        except Exception as e:
            logger.error("Image processing error occurred")
            return "Error processing image: file could not be processed"

    async def _process_json(self, content: str) -> str:
        """
        Process JSON content.
        """
        try:
            # Parse to validate JSON
            data = json.loads(content)

            # Convert back to formatted string for analysis
            formatted = json.dumps(data, indent=2)

            return f"JSON Content:\n{formatted}"
        except json.JSONDecodeError as e:
            # Do not echo raw content back; return sanitized error only
            return f"Invalid JSON: file could not be parsed"

    async def validate_file(self, content: str, filename: str) -> dict:
        """
        Validate file before processing.
        """
        safe_name = _safe_filename(filename)

        validation_result = {
            "valid": True,
            "filename": safe_name,
            "size": len(content) if content else 0,
            "warnings": []
        }

        # Size check
        if len(content) > 10 * 1024 * 1024:  # 10MB
            validation_result["warnings"].append("Large file - processing may be slow")

        # Content security validation
        if content:
            if _SUSPICIOUS_RE.search(content):
                validation_result["warnings"].append("Suspicious content detected and will be removed")

            # Check for PII patterns
            for pattern, _ in _PII_PATTERNS:
                if pattern.search(content):
                    validation_result["warnings"].append("PII detected and will be redacted")
                    break

        return validation_result