"""Enterprise treasury demo on the existing PrivateVault stack.

    make -C demos/treasury bootstrap up
    uv run python demos/treasury/approve.py        # terminal 2: the treasury approver
    make -C demos/treasury scripted                 # both prompt modes, scripted model
    make -C demos/treasury live                     # both prompt modes, real Claude

Two agents (accounts payable, treasury) with their own identities work a
queue of payments, liquidity moves and FX conversions against a bank
treasury policy enforced at decide. Nothing is reimplemented: decide, the
approval bridge, permits, the sidecar, the receiver gate, the receipt
chain, the audit export, the policy replay store and the open verifiers
are the shipped ones. Only the bank API and the vendor master are mocks.
"""
