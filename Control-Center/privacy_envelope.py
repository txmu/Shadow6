"""Read-only privacy-envelope policy and bounded telemetry."""
from dataclasses import dataclass

@dataclass
class EnvelopeMetrics:
    preauth_rejections: int = 0
    replay_rejections: int = 0
    resource_rejections: int = 0
    sessions: int = 0
    authenticated_sessions: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    def public(self):
        return {"schema":"shadow6.privacy-envelope-status.v1", "sessions":self.sessions,
                "authenticated_sessions":self.authenticated_sessions,
                "preauth_rejection_count":self.preauth_rejections,
                "replay_rejection_count":self.replay_rejections,
                "resource_limit_rejection_count":self.resource_rejections,
                "bytes_in":self.bytes_in, "bytes_out":self.bytes_out}

def compatibility(core):
    return {"core": core, "supported": True,
            "reason": "stream or datagram-preserving local endpoint selected from the Core boundary"}
