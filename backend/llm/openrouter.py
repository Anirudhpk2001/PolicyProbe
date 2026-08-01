"""
OpenRouter LLM Client

Client for communicating with LLMs via OpenRouter API.

SECURITY NOTES (for Unifai demo):
- No input sanitization before sending to LLM
- No response validation
- API key handling could be improved
- No rate limiting
"""
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id = policy_id
        self.reason = reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))


def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _lineaje_json
    import logging as _lineaje_logging
    import os as _lineaje_os
    import urllib.error as _lineaje_urlerr
    import urllib.request as _lineaje_urlreq
    _logger = _lineaje_logging.getLogger("lineaje.gr_client")
    url = _lineaje_os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data  # fail-open: GR_SERVICE_URL not configured
    tid = tenant_id or _lineaje_os.environ.get("GR_TENANT_ID", "")
    bearer = _lineaje_os.environ.get("GR_BEARER_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {
            "source_type": source_type,
            "destination_type": destination_type,
            params_key: {"data": data},
        }
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _lineaje_urlreq.Request(
            url.rstrip("/") + "/enforce",
            data=_lineaje_json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        with _lineaje_urlreq.urlopen(req, timeout=timeout) as resp:
            result = _lineaje_json.loads(resp.read())
    except _lineaje_urlerr.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = _lineaje_json.loads(exc.read()).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _logger.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _lineaje_os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    except Exception as exc:
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _logger.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)

import os
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class OpenRouterClient:
    """
    Client for OpenRouter API to access various LLMs.

    VULNERABILITY: Content sent to LLM without security checks.
    - No PII scanning before send
    - No prompt injection detection
    - No response validation
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
                "messages_preview": str(messages)[:200]
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
                        "response_preview": content[:200]
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
                "content": f"Context:\n{context}\n\nQuery: {user_message}"
            })
        else:
            messages.append({"role": "user", "content": user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.

        VULNERABILITY: Document content sent directly to LLM
        without PII scanning or threat detection.
        """
        # VULNERABILITY: No pre-LLM security checks
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content
        )
