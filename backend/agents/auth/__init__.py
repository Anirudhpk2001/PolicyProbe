"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

SECURITY NOTES:
- All agent communication requires valid signed tokens
- Internal flags only augment existing permissions
"""

from .agent_auth import AgentAuthenticator as BaseAgentAuthenticator, AgentIdentity, AuthResult
import sys

class AgentAuthenticator(BaseAgentAuthenticator):
    def authenticate(self, *args, **kwargs):
        result = super().authenticate(*args, **kwargs)
        if not result.is_valid:
            sys.exit("Authentication failed. Exiting agent.")
        return result

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]

RISK_CLASSIFICATION = "high"  # AI system risk classification (high|medium|low)
