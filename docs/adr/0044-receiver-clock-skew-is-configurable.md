# 0044: The receiver kit's clock tolerance is configurable

Status:     accepted
Date:       2026-11-20
Pinned by:  tests/network/test_receiver_hardened.py::test_clock_skew_setting;
            tests/receiver/test_receiver_gate.py::test_time_refusals_say_how_far_off;
            tests/receiver/test_receiver_gate.py::test_tolerance_covers_drift_up_to_its_bound;
            tests/demos/test_live_checkout_bootstrap.py::test_gate_clock_tolerance_is_set

## What forced the decision
A probe ran the live refund demo's gate with its clock shifted by libfaketime.
With the gate 45 s behind PrivateVault, every freshly minted permit was refused
as not yet valid: refunds stopped. With it 45 s ahead, a one-minute permit was
usable for 15 s. Both failed closed. `ReceiverGate` already accepted a bounded
`clock_skew` (0..30 s), but the receiver kit never set it, and the refusal said
only "permit not yet valid", so nothing pointed at the clock.

## The decision
- `PV_RECEIVER_CLOCK_SKEW_SECONDS` (whole seconds, 0..30, default 0) sets the
  gate's tolerance at both ends of a permit's window. Anything else refuses to
  start. The start-up summary states the tolerance.
- A time refusal says how far off the permit is by the receiver's clock, the
  tolerance in force, and that a just-minted permit points to clock drift
  (check NTP). The signed receipt is unchanged: it carries the reason code,
  not the detail.
- The live refund demo sets 5 s. Bootstrap version 3 regenerates older run
  directories so the setting reaches the gate.

## What this does not do
- It does not measure the issuer's clock. The offset reported is the permit's
  distance from the receiver's clock, which is drift only when the permit was
  presented promptly.
- Past 30 s, clocks must be fixed; the tolerance cannot cover it, by design: a
  wider window lets a revoked or replayed permit live longer.
- The default stays 0: deployments opt in.
