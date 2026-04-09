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

# Patterns for injection detection
_SQL_INJECTION_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE|REPLACE|MERGE)\b"
    r"|--|;|/\*|\*/|xp_|CAST\s*\(|CONVERT\s*\()",
    re.IGNORECASE,
)

_COMMAND_INJECTION_PATTERNS = re.compile(
    r"[;&|`$]|\$\(|`[^`]*`|\|\||&&|>|<|\.\./|\.\.\\",
)

_PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)",
    re.IGNORECASE,
)

_LLM_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(previous|all|above)\s+(instructions?|prompts?|context)"
    r"|system\s*prompt"
    r"|you\s+are\s+now"
    r"|jailbreak"
    r"|<\s*/?system\s*>"
    r"|<\s*/?prompt\s*>"
    r"|\[INST\]|\[/INST\]"
    r"|###\s*(Instruction|System|Human|Assistant)"
    r"|<\|im_start\|>|<\|im_end\|>)",
    re.IGNORECASE,
)

_SAFE_FILENAME_PATTERN = re.compile(r"[^\w\-. ]")

_MAX_INPUT_LENGTH = 100_000
_MAX_FILENAME_LENGTH = 255


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
        if len(value) > _MAX_INPUT_LENGTH:
            logger.warning("Input truncated: exceeded maximum length of %d", _MAX_INPUT_LENGTH)
            value = value[:_MAX_INPUT_LENGTH]

        # Escape HTML to prevent XSS
        value = html.escape(value, quote=True)

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

        return value

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.
        Prevents prompt injection and jailbreak attempts.
        """
        if not isinstance(content, str):
            raise ValueError("LLM content must be a string")

        # Normalize encoding
        content = await self.normalize_encoding(content)

        # Enforce maximum length
        if len(content) > _MAX_INPUT_LENGTH:
            logger.warning("LLM input truncated: exceeded maximum length of %d", _MAX_INPUT_LENGTH)
            content = content[:_MAX_INPUT_LENGTH]

        # Detect and strip prompt injection attempts
        if _LLM_INJECTION_PATTERNS.search(content):
            logger.warning("Potential LLM prompt injection pattern detected and stripped")
            content = _LLM_INJECTION_PATTERNS.sub("", content)

        # Escape HTML entities
        content = html.escape(content, quote=True)

        # Strip null bytes and control characters (except common whitespace)
        content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", content)

        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and injection.
        """
        if not isinstance(filename, str):
            raise ValueError("Filename must be a string")

        # Normalize encoding
        filename = await self.normalize_encoding(filename)

        # Strip directory components to prevent path traversal
        filename = os.path.basename(filename)

        # Remove or replace unsafe characters
        filename = _SAFE_FILENAME_PATTERN.sub("_", filename)

        # Strip leading dots to prevent hidden files / relative traversal
        filename = filename.lstrip(".")

        # Enforce maximum filename length
        if len(filename) > _MAX_FILENAME_LENGTH:
            name, _, ext = filename.rpartition(".")
            if ext:
                filename = name[:_MAX_FILENAME_LENGTH - len(ext) - 1] + "." + ext
            else:
                filename = filename[:_MAX_FILENAME_LENGTH]

        if not filename:
            filename = "unnamed"

        return filename

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent encoding-based attacks.
        """
        if not isinstance(content, str):
            return content

        # Normalize to NFC Unicode form to prevent homograph and encoding attacks
        content = unicodedata.normalize("NFC", content)

        # Remove null bytes
        content = content.replace("\x00", "")

        # Decode common percent-encoded sequences that could hide attacks
        # Re-encode any remaining percent sequences to their literal form
        content = re.sub(
            r"%([0-9a-fA-F]{2})",
            lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) > 0x1f else "",
            content,
        )

        return content