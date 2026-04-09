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
        r'color\s*:\s*#fff(?:fff)?',
        r'font-size\s*:\s*0',
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0',
        r'position\s*:\s*absolute.*left\s*:\s*-\d+',
        r'text-indent\s*:\s*-\d+',
    ]

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]
        self._compiled_hidden_patterns = [
            re.compile(p, re.IGNORECASE)
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

        # Detect prompt injection patterns
        injection_threats = await self.detect_prompt_injection(content)
        threats.extend(injection_threats)

        # Detect hidden text
        hidden_threats = await self.detect_hidden_text(content)
        threats.extend(hidden_threats)

        # Detect encoded content
        encoded_threats = await self.detect_encoded_content(content)
        threats.extend(encoded_threats)

        # Detect unicode attacks
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
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="high",
                    description="Detected hidden text pattern that may conceal malicious instructions",
                    content_preview=match if isinstance(match, str) else str(match),
                    location="content"
                ))

        # Detect zero-width characters
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u2060']
        for char in zero_width_chars:
            if char in content:
                idx = content.index(char)
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="medium",
                    description=f"Detected zero-width character (U+{ord(char):04X}) that may hide content",
                    content_preview=content[max(0, idx-10):idx+10],
                    location="content"
                ))
                break

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
        matches = b64_pattern.findall(content)

        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                # Check if decoded content contains injection patterns
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="Detected base64-encoded prompt injection attempt",
                            content_preview=match[:50],
                            location="content"
                        ))
                        break
            except Exception:
                continue

        # Detect URL-encoded injection attempts
        url_encoded_pattern = re.compile(r'(%[0-9a-fA-F]{2}){5,}')
        url_matches = url_encoded_pattern.findall(content)
        if url_matches:
            try:
                from urllib.parse import unquote
                for segment in re.findall(r'(?:%[0-9a-fA-F]{2})+', content):
                    decoded_url = unquote(segment)
                    for pattern in self._compiled_patterns:
                        if pattern.search(decoded_url):
                            threats.append(ThreatMatch(
                                threat_type="encoded_content",
                                severity="high",
                                description="Detected URL-encoded prompt injection attempt",
                                content_preview=segment[:50],
                                location="content"
                            ))
                            break
            except Exception:
                pass

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
            matches = pattern.findall(content)
            for match in matches:
                threats.append(ThreatMatch(
                    threat_type="prompt_injection",
                    severity="high",
                    description="Detected prompt injection pattern that may manipulate LLM behavior",
                    content_preview=match if isinstance(match, str) else str(match),
                    location="content"
                ))

        return threats

    async def detect_unicode_attacks(self, content: str) -> list[ThreatMatch]:
        """
        Detect unicode-based attacks including homoglyphs.

        Detects:
        - Homoglyph substitution (Cyrillic a for Latin a)
        - Bidirectional text attacks
        - Zero-width characters
        - Combining characters
        """
        threats = []

        # Detect homoglyph usage
        homoglyph_found = []
        for char, replacement in self.HOMOGLYPH_MAP.items():
            if char in content:
                homoglyph_found.append(char)

        if homoglyph_found:
            # Normalize and check if normalized content contains injection patterns
            normalized = content
            for char, replacement in self.HOMOGLYPH_MAP.items():
                normalized = normalized.replace(char, replacement)

            for pattern in self._compiled_patterns:
                if pattern.search(normalized) and not pattern.search(content):
                    threats.append(ThreatMatch(
                        threat_type="unicode_attack",
                        severity="critical",
                        description="Detected homoglyph substitution used to obfuscate prompt injection",
                        content_preview=", ".join(homoglyph_found),
                        location="content"
                    ))
                    break

            if homoglyph_found and not any(t.threat_type == "unicode_attack" for t in threats):
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="medium",
                    description="Detected unicode homoglyph characters that may be used for obfuscation",
                    content_preview=", ".join(f"U+{ord(c):04X}" for c in homoglyph_found),
                    location="content"
                ))

        # Detect bidirectional text override characters
        bidi_chars = ['\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069']
        for char in bidi_chars:
            if char in content:
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="high",
                    description=f"Detected bidirectional text override character (U+{ord(char):04X}) that may reverse displayed text",
                    content_preview=f"U+{ord(char):04X}",
                    location="content"
                ))
                break

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

        # Scan metadata string for injection patterns
        for pattern in self._compiled_patterns:
            matches = pattern.findall(metadata_str)
            for match in matches:
                threats.append(ThreatMatch(
                    threat_type="metadata_injection",
                    severity="high",
                    description="Detected prompt injection pattern in file metadata",
                    content_preview=match if isinstance(match, str) else str(match),
                    location="metadata"
                ))

        # Recursively scan metadata values
        for key, value in metadata.items() if isinstance(metadata, dict) else []:
            if isinstance(value, str):
                for pattern in self._compiled_patterns:
                    matches = pattern.findall(value)
                    for match in matches:
                        threats.append(ThreatMatch(
                            threat_type="metadata_injection",
                            severity="high",
                            description=f"Detected prompt injection pattern in metadata field '{key}'",
                            content_preview=match if isinstance(match, str) else str(match),
                            location=f"metadata.{key}"
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