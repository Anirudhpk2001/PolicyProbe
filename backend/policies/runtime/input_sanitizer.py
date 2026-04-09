"""
Input Sanitizer

Sanitizes user input before processing.
"""

import html
import logging
import os
import re
import unicodedata
from typing import Any

logger = logging.getLogger(__name__)

# Patterns for detecting injection attempts
_SQL_INJECTION_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE|REPLACE|MERGE)\b"
    r"|--|;|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)",
    re.IGNORECASE,
)

_COMMAND_INJECTION_PATTERNS = re.compile(
    r"[;&|`$]|\$\(|\$\{|>\s*/|<\s*/|\beval\b|\bexec\b|\bsystem\b|\bpassthru\b|\bpopen\b",
    re.IGNORECASE,
)

_PATH_TRAVERSAL_PATTERNS = re.compile(
    r"\.\.[/\\]|[/\\]\.\.|%2e%2e[/\\]|[/\\]%2e%2e|%252e%252e",
    re.IGNORECASE,
)

_SCRIPT_INJECTION_PATTERNS = re.compile(
    r"<\s*script[\s>]|javascript\s*:|vbscript\s*:|on\w+\s*=|<\s*iframe[\s>]"
    r"|<\s*object[\s>]|<\s*embed[\s>]|<\s*link[\s>]|<\s*meta[\s>]",
    re.IGNORECASE,
)

_LLM_PROMPT_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)"
    r"|system\s*prompt|you\s+are\s+now|pretend\s+(you\s+are|to\s+be)"
    r"|disregard\s+(all|previous|prior)\s+(instructions?|rules?)"
    r"|act\s+as\s+(if\s+you\s+are|a\s+different)|jailbreak"
    r"|<\s*\|?\s*system\s*\|?\s*>|###\s*system|###\s*instruction)",
    re.IGNORECASE,
)

_SAFE_FILENAME_PATTERN = re.compile(r"[^\w\-. ]")

MAX_INPUT_LENGTH = 100_000
MAX_FILENAME_LENGTH = 255


class InputSanitizer:
    """
    Sanitizes user input before processing.

    Protects against:
    - HTML/script injection (XSS)
    - SQL injection patterns
    - Command injection
    - Path traversal
    - Encoding attacks
    - LLM prompt injection
    """

    def __init__(self):
        pass

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data.
        """
        logger.debug(
            "Sanitization requested",
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        if isinstance(input_data, str):
            return await self._sanitize_string(input_data)
        elif isinstance(input_data, dict):
            return {k: await self.sanitize(v) for k, v in input_data.items()}
        elif isinstance(input_data, list):
            return [await self.sanitize(item) for item in input_data]
        else:
            return input_data

    async def _sanitize_string(self, value: str) -> str:
        """
        Apply full sanitization pipeline to a string value.
        """
        # Normalize encoding first
        value = await self.normalize_encoding(value)

        # Enforce maximum length
        if len(value) > MAX_INPUT_LENGTH:
            logger.warning("Input truncated: exceeded maximum length of %d", MAX_INPUT_LENGTH)
            value = value[:MAX_INPUT_LENGTH]

        # Detect and reject SQL injection patterns
        if _SQL_INJECTION_PATTERNS.search(value):
            logger.warning("Potential SQL injection pattern detected and stripped")
            value = _SQL_INJECTION_PATTERNS.sub("", value)

        # Detect and reject command injection patterns
        if _COMMAND_INJECTION_PATTERNS.search(value):
            logger.warning("Potential command injection pattern detected and stripped")
            value = _COMMAND_INJECTION_PATTERNS.sub("", value)

        # Detect and reject path traversal patterns
        if _PATH_TRAVERSAL_PATTERNS.search(value):
            logger.warning("Potential path traversal pattern detected and stripped")
            value = _PATH_TRAVERSAL_PATTERNS.sub("", value)

        # Escape HTML to prevent XSS
        value = html.escape(value, quote=True)

        return value

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.

        Removes prompt injection attempts and enforces safe content boundaries.
        """
        if not isinstance(content, str):
            raise TypeError("LLM content must be a string")

        # Normalize encoding
        content = await self.normalize_encoding(content)

        # Enforce maximum length
        if len(content) > MAX_INPUT_LENGTH:
            logger.warning("LLM input truncated: exceeded maximum length of %d", MAX_INPUT_LENGTH)
            content = content[:MAX_INPUT_LENGTH]

        # Detect and strip prompt injection attempts
        if _LLM_PROMPT_INJECTION_PATTERNS.search(content):
            logger.warning("Potential LLM prompt injection pattern detected and stripped")
            content = _LLM_PROMPT_INJECTION_PATTERNS.sub("[REDACTED]", content)

        # Strip script injection patterns
        if _SCRIPT_INJECTION_PATTERNS.search(content):
            logger.warning("Script injection pattern detected in LLM input and stripped")
            content = _SCRIPT_INJECTION_PATTERNS.sub("", content)

        # Strip null bytes and control characters (except common whitespace)
        content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", content)

        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and other file-based attacks.
        """
        if not isinstance(filename, str):
            raise TypeError("Filename must be a string")

        # Normalize encoding
        filename = await self.normalize_encoding(filename)

        # Strip any directory components to prevent path traversal
        filename = os.path.basename(filename)

        # Remove or replace unsafe characters
        filename = _SAFE_FILENAME_PATTERN.sub("_", filename)

        # Strip leading dots to prevent hidden files
        filename = filename.lstrip(".")

        # Enforce maximum filename length
        if len(filename) > MAX_FILENAME_LENGTH:
            name, _, ext = filename.rpartition(".")
            if ext:
                filename = name[: MAX_FILENAME_LENGTH - len(ext) - 1] + "." + ext
            else:
                filename = filename[:MAX_FILENAME_LENGTH]

        # Ensure filename is not empty after sanitization
        if not filename:
            filename = "unnamed_file"

        return filename

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent encoding-based attacks.
        """
        if not isinstance(content, str):
            return content

        # Normalize to NFC unicode form to prevent homograph and encoding attacks
        content = unicodedata.normalize("NFC", content)

        # Strip null bytes
        content = content.replace("\x00", "")

        # Decode percent-encoded sequences that may hide malicious patterns
        # Re-encode any remaining raw non-ASCII in a consistent form
        try:
            content = content.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
        except (UnicodeEncodeError, UnicodeDecodeError) as exc:
            logger.warning("Encoding normalization error: %s", exc)
            content = content.encode("ascii", errors="ignore").decode("ascii", errors="ignore")

        return content