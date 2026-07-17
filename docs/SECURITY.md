# Security Model

- Ed25519 signatures for decision records (`agent_dna/signer.py`)
- HMAC-SHA256 for multi-agent consensus votes (`agent_dna/consensus/signing.py`)
- Constant-time verification (`hmac.compare_digest`, `nacl` verify)
- Key rotation stub (`rotate_key`) in signer
- Fail-closed engine: any exception -> BLOCK
