"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Suspicious command patterns
SUSPICIOUS_PATTERNS = [
    r'\balias\b', r'\bripgrep\b', r'\bcurl\b', r'\brm\b', r'\becho\b',
    r'\bdd\b', r'\bgit\b', r'\btar\b', r'\bchmod\b', r'\bchown\b',
    r'\bfsck\b', r'\bsudo\b', r'\bwget\b', r'\bnc\b', r'\bnetcat\b',
    r'\bpython\b', r'\bperl\b', r'\bruby\b', r'\bbash\b', r'\bsh\b',
    r'\bpowershell\b', r'\bcmd\b', r'\bexec\b', r'\beval\b',
    r'\bsystem\b', r'\bpasswd\b', r'\bsudo\b', r'\bchroot\b',
    r'\bmkdir\b', r'\btouch\b', r'\bcat\b', r'\bls\b', r'\bps\b',
    r'\bkill\b', r'\bpkill\b', r'\bnmap\b', r'\bping\b',
    # Base64 encoded commands
    r'[A-Za-z0-9+/]{20,}={0,2}',
    # Leetspeak patterns
    r'\b[3e][xX][3e][cC]\b', r'\b[5s][hH][3e][lL][lL]\b',
    r'\b[4a][lL][1i][4a][5s]\b',
]

SUSPICIOUS_REGEX = re.compile('|'.join(SUSPICIOUS_PATTERNS), re.IGNORECASE)

# Singapore PII patterns
SG_PII_PATTERNS = {
    'NRIC_FIN': re.compile(r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE),
    'PASSPORT': re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
    'PHONE_SG': re.compile(r'\b(\+65[\s-]?)?[689]\d{7}\b'),
    'EMAIL': re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'DATE_OF_BIRTH': re.compile(r'\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](\d{2}|\d{4})\b'),
    'BANK_ACCOUNT': re.compile(r'\b\d{10,16}\b'),
    'CREDIT_CARD': re.compile(r'\b(?:\d[ -]?){13,16}\b'),
    'CPF': re.compile(r'\bCPF[\s:]*\d{9,12}\b', re.IGNORECASE),
    'IP_ADDRESS': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'MAC_ADDRESS': re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'),
    'GPS_COORDS': re.compile(r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b'),
    'SINGPASS': re.compile(r'\bSingPass[\s:]*\S+\b', re.IGNORECASE),
    'FULL_NAME': re.compile(r'\b([A-Z][a-z]+\s){1,3}[A-Z][a-z]+\b'),
    'AUTH_TOKEN': re.compile(r'\b(Bearer\s+[A-Za-z0-9\-._~+/]+=*|token[\s:=]+[A-Za-z0-9\-._~+/]{16,})\b', re.IGNORECASE),
    'SESSION_ID': re.compile(r'\b(session[\s:=]+[A-Za-z0-9\-]{16,})\b', re.IGNORECASE),
}

# General PII patterns (non-SG specific additions)
GENERAL_PII_PATTERNS = {
    'SSN': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'DRIVERS_LICENSE': re.compile(r'\b[A-Z]{1,2}\d{6,8}\b'),
    'VIN': re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),
    'IMEI': re.compile(r'\b\d{15,17}\b'),
}

MAX_INPUT_LENGTH = 10 * 1024 * 1024  # 10MB


def sanitize_input(content: str) -> str:
    """Validate and sanitize input content."""
    if not isinstance(content, str):
        raise ValueError("Input must be a string")
    if len(content) > MAX_INPUT_LENGTH:
        raise ValueError("Input content exceeds maximum allowed size")
    # Remove null bytes and other dangerous control characters
    content = content.replace('\x00', '')
    content = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', content)
    return content


def remove_suspicious_content(text: str) -> str:
    """Replace suspicious commands and binaries with placeholder."""
    return SUSPICIOUS_REGEX.sub('<suspicious_content_removed>', text)


def redact_sg_pii(text: str) -> str:
    """Redact Singapore PII from text."""
    for label, pattern in SG_PII_PATTERNS.items():
        text = pattern.sub('REDACTED', text)
    return text


def redact_general_pii(text: str) -> str:
    """Redact general PII from text."""
    for label, pattern in GENERAL_PII_PATTERNS.items():
        text = pattern.sub('REDACTED', text)
    return text


def apply_all_redactions(text: str) -> str:
    """Apply suspicious content removal and all PII redactions."""
    text = remove_suspicious_content(text)
    text = redact_sg_pii(text)
    text = redact_general_pii(text)
    return text


class HTMLParser:
    """
    Parses HTML files and extracts text content.
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract all text from HTML content with security sanitization.
        """
        try:
            html_content = sanitize_input(html_content)

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            text = soup.get_text(separator='\n', strip=True)

            # Apply security redactions
            text = apply_all_redactions(text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text),
                }
            )

            return text

        except ValueError as ve:
            logger.error("HTML extraction input validation error")
            return "Error: Invalid input"
        except Exception as e:
            logger.error("HTML extraction error occurred")
            return "Error extracting HTML content"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text.
        """
        try:
            html_content = sanitize_input(html_content)
        except ValueError:
            return "Error: Invalid input"

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Remove script, style, and hidden elements
        for element in soup(['script', 'style']):
            element.decompose()

        # Filter out elements with display:none or visibility:hidden inline styles
        for element in soup.find_all(style=True):
            style = element.get('style', '')
            if re.search(r'display\s*:\s*none|visibility\s*:\s*hidden', style, re.IGNORECASE):
                element.decompose()

        text = soup.get_text(separator='\n', strip=True)
        text = apply_all_redactions(text)
        return text

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags) with sanitization.
        """
        try:
            html_content = sanitize_input(html_content)

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                title_text = title.get_text()
                title_text = apply_all_redactions(title_text)
                metadata['title'] = title_text

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    # Sanitize name and content
                    name = re.sub(r'[^\w\-]', '', name)[:64]
                    content = apply_all_redactions(content)
                    metadata[name] = content

            return metadata

        except ValueError:
            logger.error("HTML metadata extraction input validation error")
            return {}
        except Exception as e:
            logger.error("HTML metadata extraction error occurred")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML with security analysis.
        """
        try:
            html_content = sanitize_input(html_content)
        except ValueError:
            return {"text": "", "metadata": {}, "warnings": ["Invalid input"]}

        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        warnings = []
        if '<suspicious_content_removed>' in text:
            warnings.append("Suspicious content was detected and removed from text.")
        if 'REDACTED' in text or any('REDACTED' in str(v) for v in metadata.values()):
            warnings.append("PII was detected and redacted from content.")

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }