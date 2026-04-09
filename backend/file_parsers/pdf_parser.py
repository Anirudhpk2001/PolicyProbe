"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES:
- Extracts text with hidden/suspicious content detection
- Detects and removes suspicious formatting and commands
- PII redaction enabled
- Input validation and sanitization applied
"""

import io
import re
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


SUSPICIOUS_COMMANDS = [
    r'\balias\b', r'\bripgrep\b', r'\bcurl\b', r'\brm\b', r'\becho\b',
    r'\bdd\b', r'\bgit\b', r'\btar\b', r'\bchmod\b', r'\bchown\b',
    r'\bfsck\b', r'\bsudo\b', r'\bwget\b', r'\bnc\b', r'\bnetcat\b',
    r'\bpython\b', r'\bperl\b', r'\bruby\b', r'\bbash\b', r'\bsh\b',
    r'\bzsh\b', r'\bpowershell\b', r'\bcmd\b', r'\bexec\b', r'\beval\b',
    r'\bsystem\b', r'\bpasswd\b', r'\bssh\b', r'\bscp\b', r'\bftp\b',
    r'\btelnet\b', r'\bnmap\b', r'\bping\b', r'\bifconfig\b', r'\biptables\b',
    r'\bcrontab\b', r'\bat\b', r'\bkill\b', r'\bpkill\b', r'\bchroot\b',
    r'\bmount\b', r'\bumount\b', r'\bformat\b', r'\bfdisk\b', r'\bmkfs\b',
    r'\bwhoami\b', r'\bid\b', r'\buname\b', r'\benv\b', r'\bset\b',
    r'\bexport\b', r'\bsource\b', r'\bcat\b', r'\bmore\b', r'\bless\b',
    r'\bhead\b', r'\btail\b', r'\bgrep\b', r'\bawk\b', r'\bsed\b',
    r'\bfind\b', r'\blocate\b', r'\bwhich\b', r'\bwhereis\b',
    r'\bxargs\b', r'\bcut\b', r'\bsort\b', r'\buniq\b', r'\bwc\b',
    r'\btee\b', r'\btr\b', r'\bbase64\b', r'\bopenssl\b', r'\bgpg\b',
    r'\bnohup\b', r'\bdisown\b', r'\bscreen\b', r'\btmux\b',
    r'\bstrace\b', r'\bltrace\b', r'\bgdb\b', r'\blldb\b',
    r'\bnc\b', r'\bsocat\b', r'\bmkfifo\b', r'\bdd\b',
    r'\/bin\/', r'\/etc\/', r'\/usr\/', r'\/var\/', r'\/tmp\/',
    r'\/proc\/', r'\/sys\/', r'\/dev\/',
    r'\bignore previous instructions\b', r'\bsystem prompt\b',
    r'\bforget your instructions\b', r'\byou are now\b',
    r'\bact as\b', r'\bpretend you are\b', r'\bjailbreak\b',
    r'\bDAN\b', r'\bdo anything now\b',
]

LEETSPEAK_PATTERNS = [
    (r'3x3c', 'exec'), (r'3v4l', 'eval'), (r'5y5t3m', 'system'),
    (r'p455w0rd', 'password'), (r'4dm1n', 'admin'), (r'r00t', 'root'),
    (r'5h3ll', 'shell'), (r'c0mm4nd', 'command'), (r'1nj3ct', 'inject'),
    (r'h4ck', 'hack'), (r'3xpl01t', 'exploit'), (r'p4yl04d', 'payload'),
    (r'byp455', 'bypass'), (r'0wn3d', 'owned'), (r'pwn3d', 'pwned'),
]

# Singapore PII patterns
SG_PII_PATTERNS = [
    # NRIC/FIN Number (S/T/F/G followed by 7 digits and a letter)
    (r'\b[STFG]\d{7}[A-Z]\b', 'NRIC/FIN'),
    # Passport Number
    (r'\b[A-Z]{1,2}\d{6,9}\b', 'PASSPORT'),
    # Singapore Phone Numbers
    (r'\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b', 'PHONE'),
    # Email addresses
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 'EMAIL'),
    # Bank Account Numbers (various formats)
    (r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{1,3}\b', 'BANK_ACCOUNT'),
    # Credit/Debit Card Numbers
    (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'CARD_NUMBER'),
    # CPF Account Number (similar to NRIC but used in financial context)
    (r'\bCPF[\s:]*[A-Z0-9]{9,12}\b', 'CPF_ACCOUNT'),
    # IP Address
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDRESS'),
    # MAC Address
    (r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', 'MAC_ADDRESS'),
    # GPS Coordinates
    (r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)\b', 'GPS_COORDINATES'),
    # Date of Birth patterns
    (r'\b(?:DOB|Date of Birth|Born on|Birth Date)[\s:]*\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b', 'DOB'),
    # Singapore NRIC with label
    (r'\b(?:NRIC|IC|FIN)[\s:]*[STFG]\d{7}[A-Z]\b', 'NRIC_LABELED'),
    # Work Permit / Student Pass
    (r'\b(?:WP|EP|SP|DP|LTVP)[\s:]*[A-Z0-9]{6,12}\b', 'WORK_PERMIT'),
    # SingPass / MyInfo identifiers
    (r'\b(?:SingPass|MyInfo)[\s:]*[A-Za-z0-9@._\-]{4,}\b', 'DIGITAL_ID'),
    # Authentication tokens / session IDs (long hex strings)
    (r'\b[0-9a-fA-F]{32,}\b', 'AUTH_TOKEN'),
    # Tax Identification Number
    (r'\b(?:TIN|Tax ID)[\s:]*[A-Z0-9]{8,12}\b', 'TAX_ID'),
    # Employee ID
    (r'\b(?:Employee ID|Emp ID|Staff ID)[\s:]*[A-Z0-9]{4,10}\b', 'EMPLOYEE_ID'),
    # Student ID
    (r'\b(?:Student ID|Matric No|Matriculation)[\s:]*[A-Z0-9]{4,10}\b', 'STUDENT_ID'),
    # Vehicle Identification Number
    (r'\b[A-HJ-NPR-Z0-9]{17}\b', 'VIN'),
    # IMEI
    (r'\b\d{15}\b', 'IMEI'),
    # Social Media Handles
    (r'\b@[A-Za-z0-9_.]{1,50}\b', 'SOCIAL_HANDLE'),
    # Residential/Mailing Address (Singapore postal code)
    (r'\b(?:Singapore\s*)?\d{6}\b', 'POSTAL_CODE'),
    # Full Name patterns (common Singapore name patterns - labeled)
    (r'\b(?:Name|Full Name|Patient Name|Customer Name)[\s:]*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}\b', 'FULL_NAME'),
    # Salary information
    (r'\b(?:Salary|Income|Pay|Wage|Compensation)[\s:]*(?:SGD|S\$|\$)?\s*[\d,]+(?:\.\d{2})?\b', 'SALARY'),
    # Insurance Policy Number
    (r'\b(?:Policy No|Policy Number|Insurance No)[\s:]*[A-Z0-9]{6,15}\b', 'INSURANCE_POLICY'),
    # Financial Transaction History
    (r'\b(?:Transaction ID|Txn ID|Ref No)[\s:]*[A-Z0-9]{8,20}\b', 'TRANSACTION_ID'),
]

# General PII patterns (non-Singapore specific)
GENERAL_PII_PATTERNS = [
    # SSN
    (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
    # Drivers License (generic)
    (r'\b(?:DL|Driver\'?s?\s+License)[\s:]*[A-Z0-9]{6,15}\b', 'DRIVERS_LICENSE'),
    # Taxpayer ID
    (r'\b(?:TIN|EIN|ITIN)[\s:]*\d{2}-\d{7}\b', 'TAX_ID'),
    # Mother's Maiden Name
    (r'\b(?:Mother\'?s?\s+Maiden\s+Name|MMN)[\s:]*[A-Za-z\s]{2,40}\b', 'MOTHERS_MAIDEN_NAME'),
    # Home Address (generic)
    (r'\b\d{1,5}\s+[A-Za-z\s]{3,50}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', 'HOME_ADDRESS'),
    # Fingerprint reference
    (r'\b(?:Fingerprint|Biometric)[\s:]*[A-Z0-9]{8,}\b', 'BIOMETRIC'),
    # Medical Record Number
    (r'\b(?:MRN|Medical Record|Patient ID)[\s:]*[A-Z0-9]{6,15}\b', 'MEDICAL_RECORD'),
    # Year of Birth
    (r'\b(?:Year of Birth|Birth Year|YOB)[\s:]*(?:19|20)\d{2}\b', 'YEAR_OF_BIRTH'),
    # Birthplace
    (r'\b(?:Birthplace|Place of Birth|Born in)[\s:]*[A-Za-z\s,]{3,50}\b', 'BIRTHPLACE'),
]


def _is_valid_pdf(pdf_bytes: bytes) -> bool:
    """Validate that the input is a valid PDF file."""
    if not pdf_bytes or len(pdf_bytes) < 4:
        return False
    if not pdf_bytes.startswith(b'%PDF'):
        return False
    if len(pdf_bytes) > 50 * 1024 * 1024:  # 50MB limit
        return False
    return True


def _sanitize_input(data: bytes) -> bytes:
    """Sanitize raw input bytes."""
    if not data:
        return b''
    # Remove null bytes
    data = data.replace(b'\x00', b'')
    return data


def _check_base64_content(text: str) -> str:
    """Detect and flag base64-encoded suspicious content."""
    base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    
    def check_b64_match(match):
        b64_str = match.group(0)
        try:
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            for pattern in SUSPICIOUS_COMMANDS:
                if re.search(pattern, decoded, re.IGNORECASE):
                    return '<suspicious_content_removed>'
        except Exception:
            pass
        return b64_str
    
    return base64_pattern.sub(check_b64_match, text)


def _check_leetspeak(text: str) -> str:
    """Detect and flag leetspeak-encoded suspicious content."""
    for leet_pattern, normal in LEETSPEAK_PATTERNS:
        if re.search(leet_pattern, text, re.IGNORECASE):
            text = re.sub(leet_pattern, '<suspicious_content_removed>', text, flags=re.IGNORECASE)
    return text


def _remove_suspicious_commands(text: str) -> str:
    """Remove suspicious commands and shell instructions from text."""
    # Check for base64 encoded content
    text = _check_base64_content(text)
    
    # Check for leetspeak
    text = _check_leetspeak(text)
    
    # Check for suspicious shell/system commands in context
    shell_context_pattern = re.compile(
        r'(?:^|\s|;|&&|\|\|)(' + '|'.join([
            r'alias\s+\w+', r'curl\s+\S+', r'rm\s+[-\w/]+',
            r'echo\s+.+', r'dd\s+if=', r'git\s+\w+',
            r'tar\s+[-\w]+', r'chmod\s+\d+', r'chown\s+\w+',
            r'fsck\s+\S+', r'ripgrep\s+\S+',
            r'sudo\s+\S+', r'wget\s+\S+', r'bash\s+\S+',
            r'sh\s+\S+', r'python\s+\S+', r'perl\s+\S+',
            r'eval\s*\(', r'exec\s*\(', r'system\s*\(',
        ]) + r')',
        re.IGNORECASE | re.MULTILINE
    )
    text = shell_context_pattern.sub('<suspicious_content_removed>', text)
    
    # Check for hidden prompt injection patterns
    injection_patterns = [
        r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?',
        r'disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?',
        r'forget\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?',
        r'you\s+are\s+now\s+(?:a|an)\s+\w+',
        r'act\s+as\s+(?:a|an)\s+\w+',
        r'pretend\s+(?:you\s+are|to\s+be)\s+',
        r'jailbreak',
        r'\bDAN\b',
        r'do\s+anything\s+now',
        r'new\s+instructions?:',
        r'system\s+prompt:',
        r'override\s+(?:safety|security|instructions?)',
        r'bypass\s+(?:safety|security|filter)',
    ]
    for pattern in injection_patterns:
        text = re.sub(pattern, '<suspicious_content_removed>', text, flags=re.IGNORECASE)
    
    return text


def _redact_pii(text: str) -> str:
    """Redact Singapore and general PII from text."""
    # Apply Singapore PII patterns
    for pattern, pii_type in SG_PII_PATTERNS:
        text = re.sub(pattern, 'REDACTED', text, flags=re.IGNORECASE)
    
    # Apply general PII patterns
    for pattern, pii_type in GENERAL_PII_PATTERNS:
        text = re.sub(pattern, 'REDACTED', text, flags=re.IGNORECASE)
    
    return text


def _sanitize_text(text: str) -> str:
    """Sanitize extracted text for security issues."""
    if not text:
        return text
    
    # Remove null bytes and control characters (except newlines and tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    
    # Remove suspicious commands
    text = _remove_suspicious_commands(text)
    
    # Redact PII
    text = _redact_pii(text)
    
    return text


def _sanitize_metadata_value(value: str) -> str:
    """Sanitize a metadata value."""
    if not isinstance(value, str):
        value = str(value)
    # Remove control characters
    value = re.sub(r'[\x00-\x1f\x7f]', '', value)
    # Remove suspicious content
    value = _remove_suspicious_commands(value)
    # Redact PII
    value = _redact_pii(value)
    # Limit length
    if len(value) > 1000:
        value = value[:1000] + '...[truncated]'
    return value


class PDFParser:
    """
    Parses PDF files and extracts text content.

    Security controls applied:
    - Input validation and sanitization
    - Hidden/suspicious content detection
    - PII redaction (Singapore and general)
    - Suspicious command removal
    - Prompt injection detection
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract text from a PDF file with security controls applied.
        """
        try:
            # Input validation
            if not isinstance(pdf_bytes, bytes):
                logger.warning("Invalid input type for PDF extraction")
                return "Error: Invalid input type"

            pdf_bytes = _sanitize_input(pdf_bytes)

            if not _is_valid_pdf(pdf_bytes):
                logger.warning("Invalid or oversized PDF file rejected")
                return "Error: Invalid PDF file"

            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            if len(reader.pages) > 1000:
                logger.warning("PDF exceeds maximum page limit")
                return "Error: PDF exceeds maximum allowed pages"

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    # Sanitize extracted text (remove suspicious content, redact PII)
                    sanitized_text = _sanitize_text(page_text)
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
            return "Error extracting PDF: An error occurred during processing"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata with security controls applied.
        """
        try:
            # Input validation
            if not isinstance(pdf_bytes, bytes):
                logger.warning("Invalid input type for PDF metadata extraction")
                return {}

            pdf_bytes = _sanitize_input(pdf_bytes)

            if not _is_valid_pdf(pdf_bytes):
                logger.warning("Invalid or oversized PDF file rejected for metadata extraction")
                return {}

            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                allowed_keys = {
                    '/Title', '/Author', '/Subject', '/Creator',
                    '/Producer', '/CreationDate', '/ModDate', '/Keywords'
                }
                for key in reader.metadata:
                    # Only extract known safe metadata keys
                    if key in allowed_keys:
                        sanitized_key = re.sub(r'[^\w/]', '', str(key))[:50]
                        sanitized_value = _sanitize_metadata_value(reader.metadata[key])
                        metadata[sanitized_key] = sanitized_value

            return metadata

        except Exception as e:
            logger.error("PDF metadata extraction error occurred")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF with security controls applied.
        """
        # Input validation
        if not isinstance(pdf_bytes, bytes):
            logger.warning("Invalid input type for PDF extract_all")
            return {"text": "", "metadata": {}, "warnings": ["Invalid input type"]}

        pdf_bytes = _sanitize_input(pdf_bytes)

        if not _is_valid_pdf(pdf_bytes):
            logger.warning("Invalid or oversized PDF file rejected in extract_all")
            return {"text": "", "metadata": {}, "warnings": ["Invalid PDF file"]}

        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        warnings = []
        if '<suspicious_content_removed>' in text:
            warnings.append("Suspicious content was detected and removed from the document.")
        if 'REDACTED' in text:
            warnings.append("PII data was detected and redacted from the document.")

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }