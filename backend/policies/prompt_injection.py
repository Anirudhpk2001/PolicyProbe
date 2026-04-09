"""
Prompt Injection Detection Module

Detects malicious/hidden prompts in content that could manipulate LLM behavior.
"""

import logging
import re
import base64
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatMatch:
    """Represents a detected threat."""
    threat_type: str
    severity: str  # low, medium, high, critical
    description: str
    content_preview: str
    location: str


@dataclass
class ThreatDetectionResult:
    """Result of threat detection scan."""
    has_violations: bool
    threats: list[ThreatMatch] = field(default_factory=list)
    scanned_content_length: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "threats": [
                {
                    "type": t.threat_type,
                    "severity": t.severity,
                    "description": t.description,
                    "preview": t.content_preview[:50] + "..." if len(t.content_preview) > 50 else t.content_preview,
                    "location": t.location
                }
                for t in self.threats
            ],
            "scanned_content_length": self.scanned_content_length
        }


class PromptInjectionDetector:
    """
    Detects prompt injection and hidden malicious content.

    Threat Categories:
    - hidden_text: Invisible/hidden text in documents
    - encoded_content: Base64 or otherwise encoded malicious content
    - prompt_injection: Direct prompt injection attempts
    - unicode_attack: Homoglyph or unicode-based attacks
    - metadata_injection: Malicious content in file metadata
    """

    # Known prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"disregard\s+(previous|all|above)\s+(instructions?|context)",
        r"new\s+instructions?:",
        r"system\s*:\s*you\s+are",
        r"admin\s+override",
        r"developer\s+mode",
        r"jailbreak",
        r"\[INST\]",
        r"<\|im_start\|>",
        r"###\s*(instruction|system|human|assistant)",
    ]

    # Unicode homoglyphs that could be used for attacks
    HOMOGLYPH_MAP = {
        'а': 'a',  # Cyrillic
        'е': 'e',
        'о': 'o',
        'р': 'p',
        'с': 'c',
        'х': 'x',
        # Add more as needed
    }

    # Hidden text CSS patterns
    HIDDEN_TEXT_PATTERNS = [
        r'color\s*:\s*white',
        r'font-size\s*:\s*0',
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0',
        r'position\s*:\s*absolute.*left\s*:\s*-\d+',
        r'overflow\s*:\s*hidden.*height\s*:\s*0',
    ]

    # Zero-width and invisible unicode characters
    ZERO_WIDTH_CHARS = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\u2060',  # Word joiner
        '\ufeff',  # Zero-width no-break space
        '\u00ad',  # Soft hyphen
    ]

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]
        self._compiled_hidden_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.HIDDEN_TEXT_PATTERNS
        ]

    async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
        """
        Scan content for prompt injection and hidden threats.

        Args:
            content: Content to scan for threats
            source: Source of the content (for logging)

        Returns:
            ThreatDetectionResult with detected threats
        """
        if not content:
            return ThreatDetectionResult(
                has_violations=False,
                threats=[],
                scanned_content_length=0
            )

        logger.debug(
            "Threat scan requested",
            extra={
                "source": source,
                "content_length": len(content),
            }
        )

        threats = []

        # Check for prompt injection patterns
        injection_threats = await self.detect_prompt_injection(content)
        threats.extend(injection_threats)

        # Check for hidden text
        hidden_threats = await self.detect_hidden_text(content)
        threats.extend(hidden_threats)

        # Check for encoded content
        encoded_threats = await self.detect_encoded_content(content)
        threats.extend(encoded_threats)

        # Check for unicode attacks
        unicode_threats = await self.detect_unicode_attacks(content)
        threats.extend(unicode_threats)

        has_violations = len(threats) > 0

        if has_violations:
            logger.warning(
                "Threats detected in content",
                extra={
                    "source": source,
                    "threat_count": len(threats),
                    "threat_types": list({t.threat_type for t in threats})
                }
            )

        return ThreatDetectionResult(
            has_violations=has_violations,
            threats=threats,
            scanned_content_length=len(content)
        )

    async def detect_hidden_text(self, content: str) -> list[ThreatMatch]:
        """
        Detect hidden text patterns in content.

        Detects:
        - White text on white background (CSS)
        - Zero-size text
        - Off-screen positioned text
        - Display:none content
        - Visibility:hidden content
        """
        threats = []

        for pattern in self._compiled_hidden_patterns:
            matches = pattern.findall(content)
            for match in matches:
                preview = match if isinstance(match, str) else str(match)
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="high",
                    description="Detected hidden text pattern that may conceal malicious instructions",
                    content_preview=preview[:200],
                    location="content"
                ))

        # Check for zero-width characters
        for char in self.ZERO_WIDTH_CHARS:
            if char in content:
                idx = content.index(char)
                context_start = max(0, idx - 20)
                context_end = min(len(content), idx + 20)
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="medium",
                    description=f"Detected zero-width/invisible unicode character (U+{ord(char):04X})",
                    content_preview=repr(content[context_start:context_end]),
                    location=f"offset:{idx}"
                ))

        return threats

    async def detect_encoded_content(self, content: str) -> list[ThreatMatch]:
        """
        Detect and decode potentially malicious encoded content.

        Detects:
        - Base64 encoded prompts
        - URL encoded content
        - Unicode escape sequences
        - HTML entities
        """
        threats = []

        # Detect base64 encoded content
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        matches = b64_pattern.finditer(content)
        for match in matches:
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate).decode('utf-8')
                # Check if decoded content contains injection patterns
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="Detected base64-encoded prompt injection attempt",
                            content_preview=decoded[:200],
                            location=f"offset:{match.start()}"
                        ))
                        break
                # Check for suspicious decoded content even without known patterns
                if len(decoded) > 10 and any(
                    kw in decoded.lower() for kw in [
                        'instruction', 'system', 'ignore', 'override', 'prompt', 'assistant', 'jailbreak'
                    ]
                ):
                    threats.append(ThreatMatch(
                        threat_type="encoded_content",
                        severity="high",
                        description="Detected base64-encoded content with suspicious keywords",
                        content_preview=decoded[:200],
                        location=f"offset:{match.start()}"
                    ))
            except Exception:
                continue

        # Detect URL-encoded content
        url_encoded_pattern = re.compile(r'(%[0-9A-Fa-f]{2}){5,}')
        for match in url_encoded_pattern.finditer(content):
            try:
                from urllib.parse import unquote
                decoded = unquote(match.group(0))
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="Detected URL-encoded prompt injection attempt",
                            content_preview=decoded[:200],
                            location=f"offset:{match.start()}"
                        ))
                        break
            except Exception:
                continue

        # Detect unicode escape sequences
        unicode_escape_pattern = re.compile(r'(\\u[0-9A-Fa-f]{4}){3,}')
        for match in unicode_escape_pattern.finditer(content):
            try:
                decoded = match.group(0).encode('utf-8').decode('unicode_escape')
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="Detected unicode-escaped prompt injection attempt",
                            content_preview=decoded[:200],
                            location=f"offset:{match.start()}"
                        ))
                        break
            except Exception:
                continue

        return threats

    async def detect_prompt_injection(self, content: str) -> list[ThreatMatch]:
        """
        Detect known prompt injection patterns.

        Detects patterns like:
        - "ignore previous instructions"
        - "new system prompt"
        - Role-playing attacks
        - Delimiter injection
        """
        threats = []

        for pattern in self._compiled_patterns:
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                start = match.start()
                context_start = max(0, start - 30)
                context_end = min(len(content), start + len(matched_text) + 30)
                context = content[context_start:context_end]
                threats.append(ThreatMatch(
                    threat_type="prompt_injection",
                    severity="high",
                    description=f"Detected prompt injection pattern: '{matched_text}'",
                    content_preview=context[:200],
                    location=f"offset:{start}"
                ))

        return threats

    async def detect_unicode_attacks(self, content: str) -> list[ThreatMatch]:
        """
        Detect unicode-based attacks including homoglyphs.

        Detects:
        - Homoglyph substitution (Cyrillic a for Latin a)
        - Bidirectional text attacks
        - Zero-width characters (also handled in hidden text)
        - Combining characters
        """
        threats = []

        # Detect homoglyph usage
        homoglyph_found = []
        for char, latin_equiv in self.HOMOGLYPH_MAP.items():
            if char in content:
                homoglyph_found.append(f"U+{ord(char):04X} (looks like '{latin_equiv}')")

        if homoglyph_found:
            # Normalize content and check if injection patterns appear after normalization
            normalized = content
            for char, latin_equiv in self.HOMOGLYPH_MAP.items():
                normalized = normalized.replace(char, latin_equiv)

            for pattern in self._compiled_patterns:
                if pattern.search(normalized) and not pattern.search(content):
                    threats.append(ThreatMatch(
                        threat_type="unicode_attack",
                        severity="critical",
                        description=f"Detected homoglyph-obfuscated prompt injection using characters: {', '.join(homoglyph_found)}",
                        content_preview=content[:200],
                        location="content"
                    ))
                    break
            else:
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="medium",
                    description=f"Detected unicode homoglyph characters that may be used for obfuscation: {', '.join(homoglyph_found)}",
                    content_preview=content[:200],
                    location="content"
                ))

        # Detect bidirectional text control characters
        bidi_chars = [
            ('\u202a', 'LEFT-TO-RIGHT EMBEDDING'),
            ('\u202b', 'RIGHT-TO-LEFT EMBEDDING'),
            ('\u202c', 'POP DIRECTIONAL FORMATTING'),
            ('\u202d', 'LEFT-TO-RIGHT OVERRIDE'),
            ('\u202e', 'RIGHT-TO-LEFT OVERRIDE'),
            ('\u2066', 'LEFT-TO-RIGHT ISOLATE'),
            ('\u2067', 'RIGHT-TO-LEFT ISOLATE'),
            ('\u2068', 'FIRST STRONG ISOLATE'),
            ('\u2069', 'POP DIRECTIONAL ISOLATE'),
            ('\u200f', 'RIGHT-TO-LEFT MARK'),
        ]

        for char, name in bidi_chars:
            if char in content:
                idx = content.index(char)
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="high",
                    description=f"Detected bidirectional text control character: {name} (U+{ord(char):04X})",
                    content_preview=repr(content[max(0, idx-20):min(len(content), idx+20)]),
                    location=f"offset:{idx}"
                ))

        return threats

    async def scan_metadata(self, metadata: dict) -> ThreatDetectionResult:
        """
        Scan file metadata for hidden threats.

        Scans:
        - EXIF comments and descriptions
        - PDF metadata fields
        - Document properties
        - Custom metadata tags
        """
        threats = []
        metadata_str = str(metadata)

        # Scan metadata values for injection patterns
        def scan_value(value: Any, key: str = "unknown") -> list[ThreatMatch]:
            found = []
            if isinstance(value, str):
                for pattern in self._compiled_patterns:
                    for match in pattern.finditer(value):
                        found.append(ThreatMatch(
                            threat_type="metadata_injection",
                            severity="high",
                            description=f"Detected prompt injection in metadata field '{key}': '{match.group(0)}'",
                            content_preview=value[:200],
                            location=f"metadata:{key}"
                        ))
            elif isinstance(value, dict):
                for k, v in value.items():
                    found.extend(scan_value(v, key=str(k)))
            elif isinstance(value, (list, tuple)):
                for i, item in enumerate(value):
                    found.extend(scan_value(item, key=f"{key}[{i}]"))
            return found

        for k, v in metadata.items():
            threats.extend(scan_value(v, key=str(k)))

        # Also scan the full metadata string for encoded content
        encoded_threats = await self.detect_encoded_content(metadata_str)
        for t in encoded_threats:
            threats.append(ThreatMatch(
                threat_type="metadata_injection",
                severity=t.severity,
                description=f"Detected encoded content in metadata: {t.description}",
                content_preview=t.content_preview,
                location=f"metadata:{t.location}"
            ))

        return ThreatDetectionResult(
            has_violations=len(threats) > 0,
            threats=threats,
            scanned_content_length=len(metadata_str)
        )

    def _decode_base64(self, content: str) -> Optional[str]:
        """Attempt to decode base64 content."""
        try:
            # Look for base64-like strings
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, content)

            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    return decoded
                except Exception:
                    continue
            return None
        except Exception:
            return None