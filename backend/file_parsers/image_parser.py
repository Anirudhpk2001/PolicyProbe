"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES:
- EXIF metadata extracted with security scanning
- Comments and descriptions are scanned for prompt injections
- PII redaction applied to all text fields
"""

import io
import re
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


SUSPICIOUS_PATTERNS = [
    r'\balias\b', r'\bripgrep\b', r'\bcurl\b', r'\brm\b', r'\becho\b',
    r'\bdd\b', r'\bgit\b', r'\btar\b', r'\bchmod\b', r'\bchown\b', r'\bfsck\b',
    r'\bwget\b', r'\bnc\b', r'\bnetcat\b', r'\bsudo\b', r'\bsu\b',
    r'\bchroot\b', r'\bmount\b', r'\bumount\b', r'\bkill\b', r'\bpkill\b',
    r'\bexec\b', r'\beval\b', r'\bsystem\b', r'\bpasswd\b', r'\bshadow\b',
    r'\biptables\b', r'\bnmap\b', r'\bssh\b', r'\bscp\b', r'\brsync\b',
    r'\bpython\b', r'\bperl\b', r'\bruby\b', r'\bbash\b', r'\bsh\b',
    r'\bpowershell\b', r'\bcmd\b', r'\bformat\b', r'\bdel\b', r'\brd\b',
    r'\bcat\b', r'\bgrep\b', r'\bawk\b', r'\bsed\b', r'\bfind\b',
    r'\bxargs\b', r'\bchmod\b', r'\benv\b', r'\bexport\b', r'\bset\b',
    r'\bunset\b', r'\bsource\b', r'\b\.\s*/', r'\b/etc/passwd\b',
    r'\b/etc/shadow\b', r'\b/bin/sh\b', r'\b/bin/bash\b',
    r'[0-9a-zA-Z+/]{20,}={0,2}',
    r'\b[Ss]yst3m\b', r'\b[Ee]x[Ee][Cc]\b', r'\b[Pp]ython\b',
    r'\b[Ss][Hh][Ee][Ll][Ll]\b', r'\b[Cc][Mm][Dd]\b',
    r'\bignore previous instructions\b', r'\bforget your instructions\b',
    r'\bact as\b', r'\byou are now\b', r'\bpretend you are\b',
    r'\bsystem prompt\b', r'\boverride instructions\b',
]

SUSPICIOUS_REGEX = re.compile('|'.join(SUSPICIOUS_PATTERNS), re.IGNORECASE)


def _is_base64(s: str) -> bool:
    try:
        if len(s) % 4 == 0 and len(s) >= 20:
            decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
            if any(re.search(p, decoded, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS):
                return True
    except Exception:
        pass
    return False


def scan_and_clean_suspicious(text: str) -> str:
    if not text:
        return text
    cleaned = SUSPICIOUS_REGEX.sub('<suspicious_content_removed>', text)
    words = cleaned.split()
    result_words = []
    for word in words:
        if _is_base64(word):
            result_words.append('<suspicious_content_removed>')
        else:
            result_words.append(word)
    return ' '.join(result_words)


SG_PII_PATTERNS = [
    (r'\b[STFGM]\d{7}[A-Z]\b', 'REDACTED'),
    (r'\b[A-Z]{1,2}\d{6,9}\b', 'REDACTED'),
    (r'\bSingPass\s*\S+', 'REDACTED'),
    (r'\bMyInfo\s*\S+', 'REDACTED'),
    (r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', 'REDACTED'),
    (r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b', 'REDACTED'),
    (r'\b\+65[-\s]?\d{4}[-\s]?\d{4}\b', 'REDACTED'),
    (r'\b[689]\d{7}\b', 'REDACTED'),
    (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'REDACTED'),
    (r'\b\d{3}[-\s]?\d{6}[-\s]?\d{1}\b', 'REDACTED'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'REDACTED'),
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'REDACTED'),
    (r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', 'REDACTED'),
    (r'\b\d{15,16}\b', 'REDACTED'),
    (r'\bCPF\s*\d+', 'REDACTED'),
    (r'\bEmp(?:loyee)?\s*(?:ID|Id|#)?\s*[:\-]?\s*\w+', 'REDACTED'),
    (r'\b(?:Blk|Block|No\.?)\s+\d+[A-Za-z]?\s+\w+(?:\s+\w+)*\s+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Place|Pl|Crescent|Cres|Way|Walk|Close|Cl|Terrace|Ter)\b', 'REDACTED'),
    (r'\bSingapore\s+\d{6}\b', 'REDACTED'),
    (r'\b\d{6}\b(?=\s*Singapore)', 'REDACTED'),
    (r'\b(?:GPS|Lat(?:itude)?|Lon(?:gitude)?)\s*[:\-]?\s*[-+]?\d+\.\d+', 'REDACTED'),
    (r'[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}', 'REDACTED'),
    (r'\b(?:IMEI|IMSI)\s*[:\-]?\s*\d{10,20}\b', 'REDACTED'),
    (r'\bSession(?:Id|Token|Identifier)\s*[:\-]?\s*\S+', 'REDACTED'),
    (r'\bAuth(?:entication)?[-_]?[Tt]oken\s*[:\-]?\s*\S+', 'REDACTED'),
    (r'\b(?:salary|income|wage)\s*[:\-]?\s*\$?\d+(?:[,\.]\d+)*', 'REDACTED'),
]

GENERAL_PII_PATTERNS = [
    (r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b', 'REDACTED'),
    (r'\b[A-Z]{1,2}\d{6,9}\b', 'REDACTED'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'REDACTED'),
    (r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', 'REDACTED'),
    (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'REDACTED'),
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'REDACTED'),
    (r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', 'REDACTED'),
    (r'\b(?:IMEI|IMSI)\s*[:\-]?\s*\d{10,20}\b', 'REDACTED'),
    (r'[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}', 'REDACTED'),
    (r'\b(?:Emp(?:loyee)?[-_]?ID|Employee[-_]?Number)\s*[:\-]?\s*\w+', 'REDACTED'),
    (r'\b(?:Student[-_]?ID|School[-_]?ID)\s*[:\-]?\s*\w+', 'REDACTED'),
    (r'\bVIN\s*[:\-]?\s*[A-HJ-NPR-Z0-9]{17}\b', 'REDACTED'),
    (r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', 'REDACTED'),
    (r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b', 'REDACTED'),
]


def redact_pii(text: str) -> str:
    if not text:
        return text
    for pattern, replacement in SG_PII_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    for pattern, replacement in GENERAL_PII_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def sanitize_text(text: str) -> str:
    if not text:
        return text
    text = scan_and_clean_suspicious(text)
    text = redact_pii(text)
    return text


class ImageParser:
    """
    Parses image files and extracts metadata with security scanning.
    """

    def __init__(self):
        pass

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image with security scanning.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = str(value)
                    if isinstance(value, str):
                        value = sanitize_text(value)
                    metadata[tag] = value

            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                }
            )

            return metadata

        except Exception as e:
            logger.error("Image metadata extraction error occurred")
            return {"error": "Failed to extract image metadata"}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields with security scanning.
        """
        text_fields = []

        text_field_names = [
            'ImageDescription',
            'XPComment',
            'XPSubject',
            'XPTitle',
            'XPKeywords',
            'UserComment',
            'Comment',
            'Artist',
            'Copyright',
            'Software',
        ]

        for field in text_field_names:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    value = sanitize_text(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        "Found text in metadata field",
                        extra={
                            "field": field,
                        }
                    )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis with security scanning.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        image_format = sanitize_text(str(metadata.get('format', 'unknown')))
        image_size = str(metadata.get('size', 'unknown'))
        result_parts.append(f"Image Info: {image_format} {image_size}")

        return '\n\n'.join(result_parts)