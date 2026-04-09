"""
OpenRouter LLM Client

Client for communicating with LLMs via OpenRouter API.

SECURITY NOTES (for Unifai demo):
- Input sanitization applied before sending to LLM
- Response validation applied
- API key handling improved
- Rate limiting recommended at infrastructure level
"""

import os
import re
import base64
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Approved LLM models allowlist
APPROVED_MODELS = [
    "meta-llama/llama-3-70b-instruct",
    "meta-llama/llama-3-8b-instruct",
    "mistralai/mistral-7b-instruct",
    "mistralai/mixtral-8x7b-instruct",
    "anthropic/claude-3-haiku",
    "anthropic/claude-3-sonnet",
    "anthropic/claude-3-opus",
    "openai/gpt-4o",
    "openai/gpt-4-turbo",
    "openai/gpt-3.5-turbo",
]

# PII redaction patterns (zero-tolerance categories only)
PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED-SSN]'),
    (re.compile(r'\b\d{9}\b(?=\s|$)'), '[REDACTED-SSN]'),
    # Year of Birth (standalone 4-digit year in context)
    (re.compile(r'\b(born|birth year|year of birth)[:\s]+\d{4}\b', re.IGNORECASE), '[REDACTED-YOB]'),
    # Personal Phone Number
    (re.compile(r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[REDACTED-PHONE]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
    # Home Address (basic pattern)
    (re.compile(r'\b\d{1,5}\s+\w+(\s+\w+){0,3}\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED-ADDRESS]'),
    # Passport Number
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED-PASSPORT]'),
    # Drivers License (generic pattern)
    (re.compile(r'\b(DL|DLN|Driver.?s?\s+License)[:\s#]*[A-Z0-9]{5,15}\b', re.IGNORECASE), '[REDACTED-DL]'),
    # Taxpayer Identification Number
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED-TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'), '[REDACTED-CC]'),
    # Financial Account Number
    (re.compile(r'\b(account\s*#?|acct\.?\s*#?)[:\s]*\d{6,17}\b', re.IGNORECASE), '[REDACTED-ACCOUNT]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED-IP]'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED-MAC]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED-VIN]'),
    # Employee ID
    (re.compile(r'\b(employee\s*id|emp\s*id)[:\s#]*[A-Z0-9]{4,12}\b', re.IGNORECASE), '[REDACTED-EMPID]'),
    # School ID
    (re.compile(r'\b(school\s*id|student\s*id)[:\s#]*[A-Z0-9]{4,12}\b', re.IGNORECASE), '[REDACTED-SCHOOLID]'),
]

# Dynamic code execution primitives to detect in LLM responses
DANGEROUS_CODE_PATTERNS = [
    re.compile(r'^\s*eval\s*\(.*\)\s*;?\s*$', re.MULTILINE),
    re.compile(r'^\s*exec\s*\(.*\)\s*;?\s*$', re.MULTILINE),
    re.compile(r'^\s*subprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True.*\)\s*;?\s*$', re.MULTILINE),
    re.compile(r'^\s*os\s*\.\s*system\s*\(.*\)\s*;?\s*$', re.MULTILINE),
    re.compile(r'^\s*os\s*\.\s*popen\s*\(.*\)\s*;?\s*$', re.MULTILINE),
    re.compile(r'<script\b[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'^\s*`[^`]*`\s*$', re.MULTILINE),  # bash backtick execution
    re.compile(r'^\s*\$\([^)]*\)\s*$', re.MULTILINE),  # bash $() execution
]

# Prompt injection / suspicious content patterns
PROMPT_INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+(a\s+)?(different|new|another)', re.IGNORECASE),
    re.compile(r'act\s+as\s+(if\s+you\s+are|a\s+)', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'DAN\s+mode', re.IGNORECASE),
    re.compile(r'developer\s+mode', re.IGNORECASE),
    re.compile(r'system\s+prompt\s*:', re.IGNORECASE),
    re.compile(r'\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>', re.IGNORECASE),
]

# Invisible/hidden prompt patterns
HIDDEN_PROMPT_PATTERNS = [
    # Base64 encoded content (long base64 strings)
    re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    # Leetspeak patterns
    re.compile(r'\b[1!][Gg][Nn][0Oo][Rr][Ee]\b'),
    # Zero-width characters (invisible text)
    re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]'),
    # HTML/CSS hidden text patterns
    re.compile(r'color\s*:\s*white', re.IGNORECASE),
    re.compile(r'font-size\s*:\s*0', re.IGNORECASE),
    re.compile(r'visibility\s*:\s*hidden', re.IGNORECASE),
    re.compile(r'display\s*:\s*none', re.IGNORECASE),
    # Binary executable signatures
    re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]{4,}'),
]

# Shell command patterns in prompts
SHELL_COMMAND_PATTERNS = [
    re.compile(r';\s*(rm|wget|curl|chmod|chown|sudo|su|bash|sh|zsh|python|perl|ruby|nc|netcat)\s+', re.IGNORECASE),
    re.compile(r'\|\s*(bash|sh|zsh|python|perl|ruby)\s*', re.IGNORECASE),
    re.compile(r'`[^`]{1,200}`'),
    re.compile(r'\$\([^)]{1,200}\)'),
    re.compile(r'&&\s*(rm|wget|curl|chmod|chown|sudo|su|bash|sh)\s+', re.IGNORECASE),
]


def redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from text."""
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _is_base64_encoded_prompt(text: str) -> bool:
    """Check if text contains suspicious base64 encoded content."""
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    matches = b64_pattern.findall(text)
    for match in matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            # Check if decoded content contains suspicious instructions
            for pattern in PROMPT_INJECTION_PATTERNS:
                if pattern.search(decoded):
                    return True
            for pattern in SHELL_COMMAND_PATTERNS:
                if pattern.search(decoded):
                    return True
        except Exception:
            pass
    return False


def sanitize_prompt(text: str) -> tuple[bool, str]:
    """
    Sanitize and validate prompt text before sending to LLM.
    Returns (is_safe, reason) tuple.
    """
    if not text or not text.strip():
        return False, "Empty prompt"

    # Check for hidden/invisible prompt techniques
    for pattern in HIDDEN_PROMPT_PATTERNS:
        if pattern.search(text):
            return False, "Prompt contains hidden or invisible content"

    # Check for shell commands
    for pattern in SHELL_COMMAND_PATTERNS:
        if pattern.search(text):
            return False, "Prompt contains shell commands"

    # Check for prompt injection
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            return False, "Prompt injection attempt detected"

    # Check for base64 encoded suspicious content
    if _is_base64_encoded_prompt(text):
        return False, "Prompt contains suspicious encoded content"

    return True, ""


def validate_and_sanitize_response(response: str) -> str:
    """
    Validate and sanitize LLM response by removing dangerous code execution primitives.
    Removes lines containing eval, exec, subprocess(shell=True), and other dynamic
    code execution patterns.
    """
    if not response:
        return response

    lines = response.splitlines(keepends=True)
    safe_lines = []
    for line in lines:
        is_dangerous = False
        for pattern in DANGEROUS_CODE_PATTERNS:
            if pattern.search(line):
                is_dangerous = True
                logger.warning("Removed dangerous code execution primitive from LLM response")
                break
        if not is_dangerous:
            safe_lines.append(line)

    return "".join(safe_lines)


def validate_model(model: str) -> bool:
    """Check if the model is in the approved allowlist."""
    return model in APPROVED_MODELS


class OpenRouterClient:
    """
    Client for OpenRouter API to access various LLMs.
    """

    BASE_URL = "https://openrouter.ai/api/v1"
    DEFAULT_MODEL = "meta-llama/llama-3-70b-instruct"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ):
        """
        Initialize the OpenRouter client.

        Args:
            api_key: OpenRouter API key (defaults to env var)
            model: Model to use (defaults to Llama 3 70B, can be overridden via OPENROUTER_MODEL env var)
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or os.getenv("OPENROUTER_MODEL") or self.DEFAULT_MODEL

        if not self.api_key:
            logger.warning(
                "OpenRouter API key not configured. "
                "Set OPENROUTER_API_KEY environment variable."
            )

        # Validate model against approved allowlist
        if not validate_model(self.model):
            logger.warning(
                f"Model '{self.model}' is not in the approved allowlist. "
                f"Please replace with an approved model from: {APPROVED_MODELS}. "
                f"Falling back to default approved model."
            )
            self.model = self.DEFAULT_MODEL

    async def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """
        Send chat completion request to OpenRouter.

        Args:
            messages: List of message dicts with role and content
            model: Override model for this request
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        if not self.api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."

        effective_model = model or self.model

        # Validate model against approved allowlist
        if not validate_model(effective_model):
            logger.warning(
                f"Requested model '{effective_model}' is not approved. "
                f"Approved models are: {APPROVED_MODELS}. "
                f"Please use an approved model. Falling back to default."
            )
            effective_model = self.DEFAULT_MODEL

        # Sanitize and validate all message content before sending to LLM
        sanitized_messages = []
        for msg in messages:
            content = msg.get("content", "")
            role = msg.get("role", "user")

            # Only validate user and system messages (not assistant messages)
            if role in ("user", "system"):
                is_safe, reason = sanitize_prompt(content)
                if not is_safe:
                    logger.warning(f"Blocked unsafe prompt content: {reason}")
                    return f"Request blocked: {reason}"
                # Redact PII from content before sending to LLM
                content = redact_pii(content)

            sanitized_messages.append({"role": role, "content": content})

        # Safe logging without PII or message content
        logger.info(
            "Sending request to OpenRouter",
            extra={
                "model": effective_model,
                "message_count": len(sanitized_messages),
                "total_content_length": sum(len(m.get("content", "")) for m in sanitized_messages),
            }
        )

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "HTTP-Referer": "https://policyprobe.demo",
                        "X-Title": "PolicyProbe Demo",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": effective_model,
                        "messages": sanitized_messages,
                        "temperature": temperature,
                        "max_tokens": max_tokens
                    },
                    timeout=60.0
                )

                response.raise_for_status()
                data = response.json()

                # Extract response content
                content = data["choices"][0]["message"]["content"]

                # Validate and sanitize LLM response
                content = validate_and_sanitize_response(content)

                # Safe logging without response content
                logger.info(
                    "Received response from OpenRouter",
                    extra={
                        "response_length": len(content),
                    }
                )

                return content

        except httpx.HTTPStatusError as e:
            logger.error(f"OpenRouter API error: {e.response.status_code}")
            return f"Error communicating with LLM: {e.response.status_code}"
        except Exception as e:
            logger.error("OpenRouter client error occurred")
            return "Error: An unexpected error occurred while communicating with the LLM."

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.
        """
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            # Redact PII from context before including
            safe_context = redact_pii(context)
            messages.append({
                "role": "user",
                "content": f"Context:\n{safe_context}\n\nQuery: {user_message}"
            })
        else:
            messages.append({"role": "user", "content": user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.
        PII is redacted and content is validated before sending to LLM.
        """
        # Redact PII from document content before sending to LLM
        safe_content = redact_pii(content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=safe_content
        )