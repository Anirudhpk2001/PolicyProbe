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
import base64
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

# Suspicious shell / system commands to detect and remove
_SUSPICIOUS_COMMANDS = re.compile(
    r'\b(alias|ripgrep|rg|curl|rm|echo|dd|git|tar|chmod|chown|fsck|wget|nc|netcat|'
    r'bash|sh|zsh|fish|python|perl|ruby|php|node|exec|eval|system|popen|subprocess|'
    r'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|'
    r'schtasks|at\.exe|cron|crontab|nmap|masscan|sqlmap|metasploit|msfconsole|'
    r'whoami|passwd|shadow|sudoers|iptables|ufw|kill|pkill|killall|reboot|shutdown|'
    r'mount|umount|fdisk|mkfs|dd|hexdump|xxd|base64|openssl|ssh|scp|sftp|ftp|'
    r'telnet|ping|traceroute|nslookup|dig|host|ifconfig|ip\s+addr|route|arp)\b',
    re.IGNORECASE
)

# Leetspeak pattern (common substitutions)
_LEETSPEAK_PATTERN = re.compile(
    r'\b[a-z0-9]*(?:[0-9][a-z]|[a-z][0-9])[a-z0-9]*\b.*(?:exec|syst3m|3val|sh3ll|'
    r'c0mm[a4]nd|[i1]nj[e3]ct|[s5]h[e3]ll|[e3]x[e3]c)',
    re.IGNORECASE
)

# Base64 encoded content (strings long enough to be encoded commands)
_BASE64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)

# Hidden prompt indicators (CSS-based)
_HIDDEN_STYLE_PATTERN = re.compile(
    r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|'
    r'color\s*:\s*(?:white|#fff(?:fff)?|rgba?\s*\(\s*255\s*,\s*255\s*,\s*255)|'
    r'font-size\s*:\s*0|width\s*:\s*0|height\s*:\s*0|'
    r'position\s*:\s*(?:absolute|fixed).*(?:left|top)\s*:\s*-\d)',
    re.IGNORECASE
)

# Singapore PII patterns
_SG_PII_PATTERNS = [
    # NRIC / FIN (S/T/F/G followed by 7 digits and a letter)
    (re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE), 'NRIC/FIN'),
    # Passport number (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), 'PASSPORT'),
    # Singapore phone numbers
    (re.compile(r'\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b'), 'PHONE'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'EMAIL'),
    # Credit / debit card numbers
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), 'CARD_NUMBER'),
    # Bank account numbers (6-16 digits)
    (re.compile(r'\b\d{6,16}\b'), 'BANK_ACCOUNT'),
    # CPF account (same format as NRIC but kept separate for clarity)
    (re.compile(r'\bCPF[\s:]*\d{7,9}\b', re.IGNORECASE), 'CPF'),
    # IP addresses
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'IP_ADDRESS'),
    # MAC addresses
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'MAC_ADDRESS'),
    # GPS coordinates
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)\b'), 'GPS'),
    # Date of birth patterns
    (re.compile(r'\b(?:dob|date of birth|born on|birth date)\s*[:\-]?\s*\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b', re.IGNORECASE), 'DOB'),
    # SingPass / MyInfo identifiers
    (re.compile(r'\b(?:singpass|myinfo)[\s_\-]?(?:id|identifier|user|account)?\s*[:\-]?\s*\S+\b', re.IGNORECASE), 'SINGPASS_MYINFO'),
    # Authentication tokens / session IDs (long hex or alphanumeric strings)
    (re.compile(r'\b(?:token|session|auth|bearer)\s*[:\-]?\s*[A-Za-z0-9_\-\.]{20,}\b', re.IGNORECASE), 'AUTH_TOKEN'),
    # Full name heuristic (Title Case two+ words) — kept conservative
    (re.compile(r'\b(?:name|full name)\s*[:\-]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b'), 'FULL_NAME'),
    # Residential / mailing address
    (re.compile(r'\b(?:blk|block|#\d{2}-\d{2,4}|singapore\s+\d{6})\b', re.IGNORECASE), 'ADDRESS'),
    # Salary / financial figures
    (re.compile(r'\b(?:salary|income|wage|pay)\s*[:\-]?\s*\$?\d[\d,]*(?:\.\d{2})?\b', re.IGNORECASE), 'SALARY'),
    # Employee / Student / School ID
    (re.compile(r'\b(?:employee|emp|student|school)\s*(?:id|no|number)\s*[:\-]?\s*[A-Za-z0-9\-]{4,}\b', re.IGNORECASE), 'ID_NUMBER'),
    # IMEI
    (re.compile(r'\b\d{15,17}\b'), 'IMEI'),
    # Social media handles
    (re.compile(r'(?:^|[\s,])@[A-Za-z0-9_]{3,50}\b'), 'SOCIAL_HANDLE'),
]

# General PII patterns (non-SG specific, from instruction 5)
_GENERAL_PII_PATTERNS = [
    # SSN (US)
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'SSN'),
    # Driver's license (generic alphanumeric)
    (re.compile(r'\b(?:drivers?\s*licen[sc]e|DL)\s*[:\-]?\s*[A-Z0-9\-]{6,15}\b', re.IGNORECASE), 'DRIVERS_LICENSE'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), 'VIN'),
    # Mother's maiden name
    (re.compile(r"\b(?:mother'?s?\s+maiden\s+name)\s*[:\-]?\s*[A-Za-z\s]+\b", re.IGNORECASE), 'MAIDEN_NAME'),
    # Fingerprint / biometric references
    (re.compile(r'\b(?:fingerprint|biometric|retina|iris\s+scan|voice\s+signature|facial\s+image)\b', re.IGNORECASE), 'BIOMETRIC_REF'),
    # Medical record references
    (re.compile(r'\b(?:medical\s+record|patient\s+id|diagnosis|prescription)\s*[:\-]?\s*\S+\b', re.IGNORECASE), 'MEDICAL_RECORD'),
    # Fine location
    (re.compile(r'\b(?:latitude|longitude|lat|lon|lng)\s*[:\-]?\s*[-+]?\d+\.\d+\b', re.IGNORECASE), 'FINE_LOCATION'),
    # Sexual orientation
    (re.compile(r'\b(?:sexual\s+orientation|sexuality)\s*[:\-]?\s*\S+\b', re.IGNORECASE), 'SEXUAL_ORIENTATION'),
    # Ethnicity
    (re.compile(r'\b(?:ethnicity|ethnic\s+group|race)\s*[:\-]?\s*\S+\b', re.IGNORECASE), 'ETHNICITY'),
    # Year of birth
    (re.compile(r'\b(?:year\s+of\s+birth|birth\s+year)\s*[:\-]?\s*(?:19|20)\d{2}\b', re.IGNORECASE), 'YEAR_OF_BIRTH'),
    # Birthplace
    (re.compile(r'\b(?:birthplace|place\s+of\s+birth|born\s+in)\s*[:\-]?\s*[A-Za-z\s,]+\b', re.IGNORECASE), 'BIRTHPLACE'),
    # Home address
    (re.compile(r'\b\d+\s+[A-Za-z\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|place|pl)\b', re.IGNORECASE), 'HOME_ADDRESS'),
    # Taxpayer ID
    (re.compile(r'\b(?:TIN|taxpayer\s+id)\s*[:\-]?\s*[A-Z0-9\-]{8,15}\b', re.IGNORECASE), 'TIN'),
]


def _is_base64_encoded_command(s: str) -> bool:
    """Try to decode a base64 string and check if it contains suspicious commands."""
    try:
        decoded = base64.b64decode(s + '==').decode('utf-8', errors='ignore')
        if _SUSPICIOUS_COMMANDS.search(decoded):
            return True
    except Exception:
        pass
    return False


def _sanitize_suspicious_content(text: str) -> str:
    """Remove shell commands, binaries, base64-encoded commands, and leetspeak commands."""
    # Replace suspicious shell/system commands
    text = _SUSPICIOUS_COMMANDS.sub('<suspicious_content_removed>', text)

    # Replace leetspeak command patterns
    text = _LEETSPEAK_PATTERN.sub('<suspicious_content_removed>', text)

    # Check and replace base64 encoded content that decodes to commands
    def replace_b64(m):
        s = m.group(0)
        if _is_base64_encoded_command(s):
            return '<suspicious_content_removed>'
        return s

    text = _BASE64_PATTERN.sub(replace_b64, text)

    return text


def _redact_pii(text: str) -> str:
    """Redact Singapore PII and general PII from text."""
    for pattern, label in _SG_PII_PATTERNS:
        text = pattern.sub('REDACTED', text)
    for pattern, label in _GENERAL_PII_PATTERNS:
        text = pattern.sub('REDACTED', text)
    return text


def _validate_and_sanitize_input(html_content: str) -> str:
    """Validate and sanitize HTML input before processing."""
    if not isinstance(html_content, str):
        raise ValueError("HTML content must be a string")

    # Limit input size to prevent DoS
    max_size = 10 * 1024 * 1024  # 10 MB
    if len(html_content) > max_size:
        raise ValueError("HTML content exceeds maximum allowed size")

    return html_content


def _check_for_hidden_prompts(soup) -> list:
    """Detect hidden prompt injection attempts in HTML elements."""
    warnings = []
    from bs4 import BeautifulSoup

    for tag in soup.find_all(True):
        style = tag.get('style', '')
        if style and _HIDDEN_STYLE_PATTERN.search(style):
            warnings.append(f"Hidden element detected (tag={tag.name}, style={style[:80]})")
            tag.decompose()
            continue

        # Check for zero/tiny font size
        if style and re.search(r'font-size\s*:\s*0', style, re.IGNORECASE):
            warnings.append(f"Zero font-size element detected")
            tag.decompose()
            continue

        # Check for off-screen positioning
        if style and re.search(r'(?:left|top)\s*:\s*-\d{3,}', style, re.IGNORECASE):
            warnings.append(f"Off-screen element detected")
            tag.decompose()
            continue

    return warnings


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    Security controls applied:
    - Hidden elements are detected and removed before extraction
    - Suspicious shell commands and binaries are replaced
    - Base64-encoded commands are detected and replaced
    - Leetspeak command patterns are detected and replaced
    - Singapore PII and general PII are redacted
    - Input is validated and sanitized before processing
    - Error messages do not leak internal details
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract visible text from HTML content with security controls applied.
        """
        try:
            html_content = _validate_and_sanitize_input(html_content)

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style', 'noscript', 'iframe', 'object', 'embed']):
                element.decompose()

            # Detect and remove hidden prompt injection elements
            _check_for_hidden_prompts(soup)

            text = soup.get_text(separator='\n', strip=True)

            # Sanitize suspicious commands and binaries
            text = _sanitize_suspicious_content(text)

            # Redact PII
            text = _redact_pii(text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text)
                    # Content preview removed to prevent sensitive data leakage in logs
                }
            )

            return text

        except ValueError as e:
            logger.error("HTML extraction validation error")
            return "Error extracting HTML: invalid input"
        except Exception as e:
            logger.error("HTML extraction error occurred")
            return "Error extracting HTML: processing failed"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text, filtering hidden elements.
        """
        try:
            html_content = _validate_and_sanitize_input(html_content)

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script, style, and non-visible elements
            for element in soup(['script', 'style', 'noscript', 'iframe', 'object', 'embed']):
                element.decompose()

            # Remove hidden elements by inspecting inline styles
            hidden_tags = []
            for tag in soup.find_all(True):
                style = tag.get('style', '')
                if style and _HIDDEN_STYLE_PATTERN.search(style):
                    hidden_tags.append(tag)
                # Remove elements with hidden attribute
                if tag.get('hidden') is not None:
                    hidden_tags.append(tag)
                # Remove aria-hidden elements
                if tag.get('aria-hidden', '').lower() == 'true':
                    hidden_tags.append(tag)

            for tag in hidden_tags:
                tag.decompose()

            text = soup.get_text(separator='\n', strip=True)

            # Sanitize suspicious commands and binaries
            text = _sanitize_suspicious_content(text)

            # Redact PII
            text = _redact_pii(text)

            return text

        except ValueError:
            logger.error("HTML visible extraction validation error")
            return "Error extracting HTML: invalid input"
        except Exception:
            logger.error("HTML visible extraction error occurred")
            return "Error extracting HTML: processing failed"

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags) with security controls.
        """
        try:
            html_content = _validate_and_sanitize_input(html_content)

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                title_text = title.get_text()
                title_text = _sanitize_suspicious_content(title_text)
                title_text = _redact_pii(title_text)
                metadata['title'] = title_text

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    # Sanitize name and content
                    name = re.sub(r'[^\w\-]', '', name)[:64]
                    content = _sanitize_suspicious_content(content)
                    content = _redact_pii(content)
                    if name:
                        metadata[name] = content

            return metadata

        except ValueError:
            logger.error("HTML metadata extraction validation error")
            return {}
        except Exception:
            logger.error("HTML metadata extraction error occurred")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML with security controls applied.
        """
        warnings = []

        try:
            html_content = _validate_and_sanitize_input(html_content)
        except ValueError:
            logger.error("HTML extract_all validation error")
            return {"text": "", "metadata": {}, "warnings": ["Input validation failed"]}

        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style', 'noscript', 'iframe', 'object', 'embed']):
                element.decompose()

            # Detect hidden prompt injection
            hidden_warnings = _check_for_hidden_prompts(soup)
            warnings.extend(hidden_warnings)

            if hidden_warnings:
                warnings.append("Hidden content detected and removed")

        except Exception:
            logger.error("HTML extract_all soup processing error")

        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }