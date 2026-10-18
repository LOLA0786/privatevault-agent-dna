# 0023: Signing keys may live in AWS KMS or Google Cloud KMS

Status:     accepted
Date:       2026-10-18
Pinned by:  tests/test_key_custody.py::test_kms_signature_is_identical_to_the_local_one;
            tests/test_key_custody.py::test_a_kms_signature_that_does_not_verify_is_refused;
            tests/test_key_custody.py::test_aws_requests_are_pure_ed25519_on_raw_bytes;
            tests/test_authorize_kms.py::test_a_kms_key_the_bundle_does_not_pin_is_refused;
            tests/test_authorize_kms.py::test_kms_outage_refuses_then_recovers

## What forced the decision
Every PrivateVault signing key was a seed in a file or an environment
variable on the API host (docs/SECURITY.md, assumption A2). Anyone who read
that host's disk or environment could mint permits, sign revocation lists
and forge decision receipts, and could copy the key off the host to keep
doing so.

## The decision
`agent_dna/key_custody.py` puts every signing operation behind one small
interface (a public key, and `sign(message)` returning a pure Ed25519
signature) with three custodians: a local key (unchanged behaviour), AWS
KMS and Google Cloud KMS. The existing settings take a reference instead of
a seed: `PV_EXECUTION_SIGNER_KEY`, `PV_RECEIPT_SIGNING_KEY`,
`PV_DISPATCH_WITNESS_KEY` and the receiver kit's `PV_RECEIPT_KEY_FILE` accept
`awskms:<key id or ARN>` or `gcpkms:<key version name>`.

Pure Ed25519 only, so no verifier changes: AWS key spec
`ECC_NIST_EDWARDS25519` with `ED25519_SHA_512` and `MessageType=RAW`; Cloud
KMS algorithm `EC_SIGN_ED25519` over raw data. (Checked against AWS's
published API model in botocore and the `google-cloud-kms` types.) The
pre-hashed variant `ED25519_PH_SHA_512` is a different signature and is
never used.

Fail closed, every time:
- the key's type and algorithm are checked when the signer is built;
- every KMS signature is verified locally against the key's public key
  before it is used, and Cloud KMS CRC32C integrity fields are checked;
- the execution signer must be the bundle entry pinned as
  `execution_authorization_signer` (previously the first bundle key was
  assumed); otherwise mint and revocation list answer 503;
- a KMS failure at mint is `AUTHORIZE_SIGNER_UNAVAILABLE` (503) and the mint
  claim rolls back, so the decision mints once the KMS is reachable.

## What this costs us
- A KMS round trip per signature: every permit, every signed decision
  receipt, every revocation list. With SQLite the mint holds the database
  write lock during that round trip; with PostgreSQL only that decision's
  lock.
- AWS signs at most 4096 bytes as pure Ed25519. A permit's canonical form is
  about 2.4 KB with small action parameters, which leaves roughly 1.7 KB for
  the parameters; a larger permit is refused, not pre-hashed. Cloud KMS has
  no such limit for these documents.
- The key never leaves the KMS, but the API host can still ask the KMS to
  sign anything while it holds the IAM permission. KMS custody removes key
  theft and gives a KMS-side audit log of every signature; it does not stop
  a compromised host from signing while compromised (WHAT-WE-DO-NOT-CLAIM:
  signing defends against alteration, not against a compromised signer).
- Tested against AWS's API model and a Cloud KMS stand-in, not a live KMS;
  `tools/kms_smoke.py` is the live check an operator runs against a real key.

## What would make us revisit
HSM attestation of the signing request, Azure Key Vault (no Ed25519 there
when this was written) or HashiCorp Vault transit, or permits that outgrow
the AWS raw-message limit.
