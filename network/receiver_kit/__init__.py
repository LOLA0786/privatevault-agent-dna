"""Receiver kit: run a PrivateVault receiver gate on your own infrastructure.

See QUICKSTART.md. The gate itself lives in ``agent_dna.receiver`` (ADR 0019);
this package only configures it from the environment and ships the pieces a
partner needs around it: key generation, a dummy upstream, a test sender, and
a receipt exporter.
"""
