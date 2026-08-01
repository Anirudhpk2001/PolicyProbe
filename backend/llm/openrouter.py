"""
OpenRouter LLM Client

Client for communicating with LLMs via OpenRouter API.

SECURITY NOTES (for Unifai demo):
- No input sanitization before sending to LLM
- No response validation
- API key handling could be improved
- No rate limiting
"""

import os
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class OpenRouterClient:

    def _sanitize_input(self, input_str: str, max_length: int = 10000) -> str:
        """Validate and sanitize input content"""
        if not input_str:
            raise ValueError("Input cannot be empty")
        
        if len(input_str) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length} characters")
        
        # Remove leading/trailing whitespace and potentially dangerous characters
        sanitized = input_str.strip().replace("\x00", "")
        
        # Basic XSS prevention
        sanitized = sanitized.replace("<", "&lt;").replace(">", "&gt;")
        
        return sanitized
    """
    Client for OpenRouter API to access various LLMs.

    VULNERABILITY: Content sent to LLM without security checks.
    - No PII scanning before send
    - No prompt injection detection
    - No response validation
    """

    BASE_URL = "https://openrouter.ai/api/v1"
    DEFAULT_MODEL = "anthropic/claude-3-opus"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        risk_classification: Optional[str] = None
    ):
        """
        Initialize the OpenRouter client.

        Args:
            api_key: OpenRouter API key (defaults to env var)
            model: Model to use (defaults to Claude 3 Opus, can be overridden via OPENROUTER_MODEL env var)
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or os.getenv("OPENROUTER_MODEL") or self.DEFAULT_MODEL
        self.risk_classification = risk_classification or os.getenv("OPENROUTER_RISK_CLASSIFICATION")

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

        VULNERABILITY: Messages sent without security scanning.
        - User content not checked for PII
        - No prompt injection filtering
        - Response not validated

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

        # VULNERABILITY: Content logged without masking
        logger.info(
            "Sending request to OpenRouter",
            extra={
                "model": model or self.model,
                "message_count": len(messages),
                "total_content_length": sum(len(m.get("content", "")) for m in messages),
                # VULNERABILITY: Message content in logs
                "messages_preview": str([{"role": m["role"], "content": "[REDACTED]"} for m in messages])[:200]
            }
        )

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                try:
                    import asyncio as _gr_asyncio
                    response = await _gr_asyncio.to_thread(gr_check, response, "api", "agent")
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError":
                        raise
                    response = response
                    import logging as _lineaje_logging
                    _lineaje_logging.getLogger("lineaje.gr_client").warning(
                        "Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked"
                    )
                    f"{self.BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "HTTP-Referer": "https://policyprobe.demo",
                        "X-Title": "PolicyProbe Demo",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model or self.model,
                        "messages": messages,
                        "temperature": temperature,
                        "max_tokens": max_tokens
                    },
                    timeout=60.0
                )

                response.raise_for_status()
                data = response.json()

                # Extract response content
                content = data["choices"][0]["message"]["content"]

                # VULNERABILITY: Response not validated for:
                # - PII leakage
                # - Harmful content
                # - Bias
                logger.info(
                    "Received response from OpenRouter",
                    extra={
                        "response_length": len(content),
                        # VULNERABILITY: Full response in logs
                        "response_preview": f'Response length: {len(content)} chars'
                    }
                )

                return content

        except httpx.HTTPStatusError as e:
            logger.error(f"OpenRouter API error: {e.response.status_code}")
            return f"Error communicating with LLM: {e.response.status_code}"
        except Exception as e:
            logger.error(f"OpenRouter client error: {e}")
            return f"Error: {str(e)}"

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.

        VULNERABILITY: No content validation.
        """
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            # VULNERABILITY: Context added without scanning
            messages.append({
                "role": "user",
                "content": f"Context:\n{self._sanitize_input(context)}\n\nQuery: {self._sanitize_input(user_message)}"
            })
        else:
            messages.append({"role": "user", "content": self._sanitize_input(user_message)})

        return await self.chat(messages)

    def check_for_sg_pii(self, text: str) -> bool:
        """Check for Singapore-specific PII patterns"""
        sg_patterns = [
            r'\b[STFG]\d{7}[A-Z]\b',  # NRIC
            r'\b(\+65|65)?\s*\d{4}\s*\d{4}\b',  # Phone numbers
            r'\b\d{6}\b',  # Postal codes
            r'\b(Singapore|SG)\s*\d{5,6}\b'  # Addresses
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in sg_patterns)

    async def analyze_document(self, content: str) -> str:
        # PII check for Singapore identifiers
        if self.check_for_sg_pii(content):
            logger.error("Document contains Singapore PII - blocking analysis")
            return "Document contains sensitive personal information and cannot be processed"
        """
        Analyze document content using LLM.

        VULNERABILITY: Document content sent directly to LLM
        without PII scanning or threat detection.
        """
        # VULNERABILITY: No pre-LLM security checks
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points. Remember to clearly state that you are an AI assistant when responding to users.",
            context=self._sanitize_input(content)
        )
