"""
PrivateVault Security Validation Framework.

Continuous adversarial testing integrated into CI/CD.

Every adversarial agent targets a real failure mode:
- Jailbreak: prompt injection / safety bypass
- Collusion: multi-agent Byzantine manipulation
- Replay: expired approval / capability replay
- Rogue MCP: malicious server / manifest swap

Scoring framework:
Prevention (40)
Detection (20)
Containment (20)
Recovery (10)
Auditability (10)

Total = 100
"""

__version__ = "0.1.0"
