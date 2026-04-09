"""
OpenRouter LLM Client

Client for communicating with LLMs via OpenRouter API.

SECURITY NOTES (for Unifai demo):
- Input sanitization applied before sending to LLM
- Response validation applied
- API key handling improved
- Rate limiting not yet implemented
"""

import os
import re
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# PII redaction patterns for zero-tolerance PII categories
PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    (re.compile(r'\b\d{9}\b'), '[REDACTED_SSN]'),
    # Year of Birth (standalone 4-digit year context)
    (re.compile(r'\b(born in|birth year|year of birth)[:\s]+\d{4}\b', re.IGNORECASE), '[REDACTED_YOB]'),
    # Personal Phone Number
    (re.compile(r'\b(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b'), '[REDACTED_PHONE]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Home Address (basic pattern)
    (re.compile(r'\b\d{1,5}\s+\w+(\s+\w+){0,3}\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Passport Number
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Drivers License (generic)
    (re.compile(r'\b(DL|DLN|Driver.?s?\s+License)[:\s#]*[A-Z0-9]{5,15}\b', re.IGNORECASE), '[REDACTED_DL]'),
    # Taxpayer Identification Number
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED_CC]'),
    # Financial Account Number
    (re.compile(r'\b(account\s*(number|#|no)?[:\s]*)\d{6,17}\b', re.IGNORECASE), '[REDACTED_ACCOUNT]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Employee ID / School ID (generic badge patterns)
    (re.compile(r'\b(employee|emp|school|student)\s*(id|#|no)?[:\s]*[A-Z0-9]{4,12}\b', re.IGNORECASE), '[REDACTED_ID]'),
]

# Prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'forget\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+(?!a\s+document)', re.IGNORECASE),
    re.compile(r'new\s+instructions?\s*:', re.IGNORECASE),
    re.compile(r'system\s*prompt\s*:', re.IGNORECASE),
    re.compile(r'<\s*/?system\s*>', re.IGNORECASE),
    re.compile(r'\[INST\]|\[/INST\]', re.IGNORECASE),
    re.compile(r'###\s*instruction', re.IGNORECASE),
    re.compile(r'act\s+as\s+(if\s+you\s+are|a\s+different)', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'DAN\s+mode', re.IGNORECASE),
]

# Dynamic code execution patterns for response validation
CODE_EXECUTION_PATTERNS = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\bsubprocess\s*\.\s*\w*\s*\(.*shell\s*=\s*True', re.IGNORECASE),
    re.compile(r'\bos\s*\.\s*system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\s*\.\s*popen\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\(', re.IGNORECASE),
    re.compile(r'\bcompile\s*\(', re.IGNORECASE),
    re.compile(r'\bexecfile\s*\(', re.IGNORECASE),
    re.compile(r'<\s*script[^>]*>', re.IGNORECASE),
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'\$\s*\(.*\)', re.IGNORECASE),
    re.compile(r'`[^`]+`'),
]


def redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from text."""
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_input(text: str) -> str:
    """Sanitize input text by redacting PII and checking for prompt injection."""
    if not text:
        return text
    # Redact PII first
    text = redact_pii(text)
    # Check for prompt injection attempts and neutralize
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning("Potential prompt injection detected and neutralized in input.")
            text = pattern.sub('[FILTERED]', text)
    return text


def validate_llm_response(response: str) -> str:
    """
    Validate LLM response by removing lines containing dynamic code-execution primitives.
    Also redacts any PII present in the response.
    """
    if not response:
        return response

    # Remove lines containing dangerous code execution patterns
    lines = response.splitlines()
    safe_lines = []
    for line in lines:
        dangerous = False
        for pattern in CODE_EXECUTION_PATTERNS:
            if pattern.search(line):
                logger.warning("Dangerous code execution pattern detected in LLM response; line removed.")
                dangerous = True
                break
        if not dangerous:
            safe_lines.append(line)

    validated = '\n'.join(safe_lines)

    # Redact any PII that may have leaked into the response
    validated = redact_pii(validated)

    return validated


def mask_pii_for_log(text: str) -> str:
    """Mask PII in text intended for logging."""
    return redact_pii(text)


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

        # Sanitize all message content before sending to LLM
        sanitized_messages = []
        for m in messages:
            sanitized_msg = dict(m)
            if "content" in sanitized_msg and isinstance(sanitized_msg["content"], str):
                sanitized_msg["content"] = sanitize_input(sanitized_msg["content"])
            sanitized_messages.append(sanitized_msg)

        logger.info(
            "Sending request to OpenRouter",
            extra={
                "model": model or self.model,
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
                        "model": model or self.model,
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
                content = validate_llm_response(content)

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
            logger.error("OpenRouter client error occurred.")
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
        # Sanitize inputs before constructing messages
        sanitized_user_message = sanitize_input(user_message)
        sanitized_system_prompt = sanitize_input(system_prompt)

        messages = [{"role": "system", "content": sanitized_system_prompt}]

        if context:
            sanitized_context = sanitize_input(context)
            messages.append({
                "role": "user",
                "content": f"Context:\n{sanitized_context}\n\nQuery: {sanitized_user_message}"
            })
        else:
            messages.append({"role": "user", "content": sanitized_user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.
        Content is sanitized and PII is redacted before sending to LLM.
        """
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content
        )