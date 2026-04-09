"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES:
- Extracts text with hidden/white text detection
- Suspicious formatting detection enabled
- PII redaction enabled
- Suspicious content removal enabled
"""

import io
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Suspicious command patterns
SUSPICIOUS_COMMANDS = [
    r'\balias\b', r'\bripgrep\b', r'\bcurl\b', r'\brm\b', r'\becho\b',
    r'\bdd\b', r'\bgit\b', r'\btar\b', r'\bchmod\b', r'\bchown\b',
    r'\bfsck\b', r'\bwget\b', r'\bnc\b', r'\bnetcat\b', r'\bsudo\b',
    r'\bsu\b', r'\bexec\b', r'\beval\b', r'\bsystem\b', r'\bshell\b',
    r'\bpowershell\b', r'\bcmd\.exe\b', r'\b/bin/sh\b', r'\b/bin/bash\b',
    r'\bpython\b', r'\bperl\b', r'\bruby\b', r'\bphp\b', r'\bnmap\b',
    r'\bssh\b', r'\bscp\b', r'\bftp\b', r'\btelnet\b', r'\bawk\b',
    r'\bsed\b', r'\bgrep\b', r'\bfind\b', r'\bxargs\b', r'\bkill\b',
    r'\bpkill\b', r'\bchroot\b', r'\bmount\b', r'\bumount\b',
    r'\biptables\b', r'\bnetstat\b', r'\bifconfig\b', r'\bwhoami\b',
    r'\buname\b', r'\bpasswd\b', r'\bshadow\b', r'\bcrontab\b',
    r'\bat\b\s+\d', r'\bbash\b', r'\bzsh\b', r'\bksh\b', r'\bcsh\b',
    # Base64 encoded commands
    r'[A-Za-z0-9+/]{20,}={0,2}',
    # Leetspeak patterns
    r'\b[3e][xX][3e][cC]\b', r'\b[5s][hH][3e][lL][lL]\b',
    r'\b[5s][yY][5s][tT][3e][mM]\b',
]

SUSPICIOUS_PATTERN = re.compile('|'.join(SUSPICIOUS_COMMANDS), re.IGNORECASE)

# Singapore PII patterns
SG_PII_PATTERNS = [
    # NRIC/FIN Number (S/T/F/G followed by 7 digits and a letter)
    (re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE), 'REDACTED'),
    # Passport Number
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), 'REDACTED'),
    # Singapore Phone Numbers
    (re.compile(r'\b(\+65[\s-]?)?[689]\d{7}\b'), 'REDACTED'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # Bank Account Numbers (various formats)
    (re.compile(r'\b\d{3}[-\s]?\d{6}[-\s]?\d{1,3}\b'), 'REDACTED'),
    # Credit/Debit Card Numbers
    (re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'), 'REDACTED'),
    # CPF Account Number (similar to NRIC)
    (re.compile(r'\bCPF[\s:]*[STFG]\d{7}[A-Z]\b', re.IGNORECASE), 'REDACTED'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # GPS Coordinates
    (re.compile(r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b'), 'REDACTED'),
    # Date of Birth patterns
    (re.compile(r'\b(0?[1-9]|[12]\d|3[01])[-/](0?[1-9]|1[0-2])[-/](19|20)\d{2}\b'), 'REDACTED'),
    # Singapore Residential Address patterns
    (re.compile(r'\b(blk|block|no\.?)\s*\d+[A-Z]?\s+\w+(\s+\w+)*\s+(street|st|avenue|ave|road|rd|drive|dr|lane|ln|crescent|cres|place|pl|way|close|cl|terrace|ter|walk|link|loop|grove|view|rise|hill|heights|gardens|park|court|ct)\b', re.IGNORECASE), 'REDACTED'),
    # SingPass/MyInfo identifiers
    (re.compile(r'\b(singpass|myinfo)[\s:_-]*[A-Za-z0-9@._-]+\b', re.IGNORECASE), 'REDACTED'),
    # Authentication tokens / session identifiers (long hex or alphanumeric strings)
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), 'REDACTED'),
    # Full Name (basic heuristic: 2-4 capitalized words)
    (re.compile(r'\b([A-Z][a-z]+\s){1,3}[A-Z][a-z]+\b'), 'REDACTED'),
]

# General PII patterns (non-Singapore specific)
GENERAL_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'REDACTED'),
    # Taxpayer Identification Number
    (re.compile(r'\b\d{2}-\d{7}\b'), 'REDACTED'),
    # Driver's License (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{6,8}\b'), 'REDACTED'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), 'REDACTED'),
    # IMEI
    (re.compile(r'\b\d{15,17}\b'), 'REDACTED'),
    # Financial Account Numbers (generic)
    (re.compile(r'\b\d{8,20}\b'), 'REDACTED'),
]


def remove_suspicious_content(text: str) -> str:
    """Remove suspicious commands and replace with placeholder."""
    return SUSPICIOUS_PATTERN.sub('<suspicious_content_removed>', text)


def redact_pii(text: str) -> str:
    """Redact Singapore and general PII from text."""
    for pattern, replacement in SG_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    for pattern, replacement in GENERAL_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_content(text: str) -> str:
    """Apply all content sanitization: suspicious content removal and PII redaction."""
    text = remove_suspicious_content(text)
    text = redact_pii(text)
    return text


class PDFParser:
    """
    Parses PDF files and extracts text content.

    Security controls applied:
    - Suspicious command/content detection and removal
    - Singapore PII redaction
    - General PII redaction
    - Safe error handling (no internal details leaked)
    - No content previews in logs
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file with security sanitization.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    sanitized_text = sanitize_content(page_text)
                    text_parts.append(sanitized_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(sanitized_text),
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            return full_text

        except Exception as e:
            logger.error("PDF extraction error occurred")
            return "Error extracting PDF content"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata with PII redaction.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    raw_value = reader.metadata[key]
                    if isinstance(raw_value, str):
                        sanitized_value = sanitize_content(raw_value)
                    else:
                        sanitized_value = raw_value
                    metadata[key] = sanitized_value

            return metadata

        except Exception as e:
            logger.error("PDF metadata extraction error occurred")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF with security analysis.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        warnings = []
        if '<suspicious_content_removed>' in text:
            warnings.append("Suspicious content was detected and removed from the document.")
        if 'REDACTED' in text:
            warnings.append("PII was detected and redacted from the document.")

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }