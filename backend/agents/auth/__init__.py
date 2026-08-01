"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

SECURITY NOTES (for Unifai demo):
- Authentication requires valid JWT token verification
- Token validation enforces signature and expiration checks
- is_internal flag requires additional multi-factor authentication
"""

from .agent_auth import AgentAuthenticator as BaseAuthenticator, AgentIdentity, AuthResult

class AgentAuthenticator(BaseAuthenticator):
    MAX_ATTEMPTS = 3
    def __init__(self):
        super().__init__()
        self.attempt_count = 0

    def authenticate(self, *args, **kwargs):
        if self.attempt_count >= self.MAX_ATTEMPTS:
            raise RuntimeError("Maximum authentication attempts exceeded")
        self.attempt_count += 1
        return super().authenticate(*args, **kwargs)

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]
