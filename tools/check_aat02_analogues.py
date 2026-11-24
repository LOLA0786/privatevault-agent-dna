"""Check the AAT -02 column of PrivateVault's delegation vectors against the
AAT reference verifier, and write each scenario as a real AAT -02 vector.

    uv run python tools/check_aat02_analogues.py --tenuo /path/to/tenuo
    uv run python tools/check_aat02_analogues.py --tenuo /path/to/tenuo --write

``--tenuo`` (or ``TENUO_DIR``) is a checkout of tenuo-ai/tenuo. Its
``ietf/vectors/gen_vectors.py`` is the reference Section 8 verifier for
draft-niyikiza-oauth-attenuating-agent-tokens-02; importing it builds its own
229 vectors in memory and writes nothing. Nothing from it is copied here.

For every vector in ``vectors/aat02/pv-delegation-2.json`` this builds the
same scenario as an AAT -02 chain with that module's helpers, driven by the
committed suite so the two cannot drift:

- each link becomes a token with the claims of its AAT view;
- a token is signed by the key that really signed the PrivateVault link
  (found by checking its signature against every published key), and a link
  whose signature verifies under no key gets a corrupted signature;
- ``par_hash`` follows the link's ``parent`` pointer: the parent's token if
  the parent is presented, otherwise a token that is not in the chain;
- the PoP is signed by the agent presenting the chain.

The verdict and step from ``verify_chain`` must equal the vector's
``aat_02``. A scenario AAT cannot express (a cumulative budget, revocation)
is skipped with its reason. ``--write`` also writes the AAT vectors to
``vectors/aat02/aat-analogues.json`` in the layout of the AAT suite, so any
AAT -02 implementation can run them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_dna.multi_agent_security.delegation import link_hash  # noqa: E402

SUITE = ROOT / "vectors" / "aat02" / "pv-delegation-2.json"
OUT = ROOT / "vectors" / "aat02" / "aat-analogues.json"


def load_reference(tenuo: Path) -> Any:
    sys.path.insert(0, str(tenuo / "ietf" / "vectors"))
    import gen_vectors  # type: ignore[import-not-found]

    return gen_vectors


def tenuo_commit(tenuo: Path) -> str:
    out = subprocess.run(
        ["git", "-C", str(tenuo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() or "unknown"


class Builder:
    """AAT -02 tokens for one suite, with the reference module's helpers."""

    def __init__(self, g: Any, suite: dict[str, Any]) -> None:
        self.g = g
        self.suite = suite
        self.keys: dict[str, Any] = {}
        self.trust = [(g.ROOT_ISS, self.key("operator").jwk)]

    def key(self, name: str) -> Any:
        if name not in self.keys:
            seed = hashlib.sha256(b"pv-aat02-analogues/" + name.encode()).digest()
            self.keys[name] = self.g.Key(name, seed)
        return self.keys[name]

    def signer_of(self, link: dict[str, Any]) -> str | None:
        """The party whose published key verifies this PrivateVault link."""
        from nacl.encoding import HexEncoder
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        for name, pub in self.suite["keys"].items():
            try:
                VerifyKey(pub.encode(), encoder=HexEncoder).verify(
                    link_hash(link).encode(), bytes.fromhex(link["signature"])
                )
                return name
            except (BadSignatureError, ValueError):
                continue
        return None

    @staticmethod
    def _time(x: float) -> int | float:
        return int(x) if float(x).is_integer() else x

    def claims(
        self, view: dict[str, Any], jti: str, signer: str, par: str | None
    ) -> dict[str, Any]:
        c: dict[str, Any] = {
            "jti": jti,
            "iss": self.g.ROOT_ISS
            if view["del_depth"] == 0
            else self.key(signer).thumbprint_uri,
            "iat": self._time(view["iat"]),
            "exp": self._time(view["exp"]),
            "del_depth": view["del_depth"],
        }
        if "del_max_depth" in view:
            c["del_max_depth"] = view["del_max_depth"]
        if par is not None:
            c["par_hash"] = par
        c["cnf"] = {"jwk": self.key(view["pv_delegate"]).jwk}
        c["authorization_details"] = self.g.aat(
            view["authorization_details"][0]["tools"]
        )
        return c

    def chain(self, v: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
        by_hash = {link_hash(e["link"]): e for e in v["chain"]}
        tokens: dict[str, dict[str, Any]] = {}

        def token(h: str) -> dict[str, Any]:
            if h in tokens:
                return tokens[h]
            entry = by_hash[h]
            link, view = entry["link"], entry["aat"]
            parent = link["parent"]
            if parent is None:
                par = None
            elif parent in by_hash:
                par = self.g.par_hash_of(token(parent))
            else:  # the parent is not presented: hash a token outside the chain
                absent = self.claims(
                    {**view, "del_depth": 0}, f"pv-{v['id']}-absent", "operator", None
                )
                par = self.g.par_hash_of(self.g.jws_sign(absent, self.key("operator")))
            signer = self.signer_of(link)
            jti = f"pv-{v['id']}-{list(by_hash).index(h)}"
            tok = self.g.jws_sign(
                self.claims(view, jti, signer or link["delegator"], par),
                self.key(signer or link["delegator"]),
            )
            if signer is None:  # verifies under no key: corrupt the signature
                head, body, sig = tok["compact"].split(".")
                mid = len(sig) // 2
                sig = sig[:mid] + ("A" if sig[mid] != "A" else "B") + sig[mid + 1 :]
                tok = {**tok, "compact": f"{head}.{body}.{sig}"}
            tokens[h] = tok
            return tok

        return [token(link_hash(e["link"]))["compact"] for e in v["chain"]], tokens

    def presentation(self, v: dict[str, Any]) -> tuple[list[str], str]:
        compacts, tokens = self.chain(v)
        leaf = tokens[link_hash(v["chain"][-1]["link"])]
        presenter = v["policy"].get("agent_id", v["chain"][-1]["link"]["delegate"])
        args, _dup = self.g._loads(v["args_json"])
        pop = self.g.pop_sign(
            self.g.pop_claims(f"pv-{v['id']}-pop", leaf, v["tool"], args, iat=v["now"]),
            self.key(presenter),
        )
        return compacts, pop["compact"]

    def verdict(
        self, compacts: list[str], pop: str, v: dict[str, Any]
    ) -> tuple[str, str | None]:
        args, dup = self.g._loads(v["args_json"])
        try:
            return self.g.verify_chain(
                compacts, self.trust, v["tool"], args, pop, now=v["now"], args_dup=dup
            ), None
        except self.g.Deny as exc:
            return "DENY", exc.step


def run(tenuo: Path, write: bool) -> int:
    g = load_reference(tenuo)
    suite = json.loads(SUITE.read_text(encoding="utf-8"))
    b = Builder(g, suite)
    rows, out, failed = [], [], 0
    for v in suite["vectors"]:
        want = v["aat_02"]
        if want["verdict"] == "n/a":
            rows.append(f"{v['id']:<6} SKIP   {want.get('note', '')}")
            continue
        compacts, pop = b.presentation(v)
        verdict, step = b.verdict(compacts, pop, v)
        ok = (verdict, step) == (want["verdict"], want.get("step"))
        failed += not ok
        got = verdict + (f"/{step}" if step else "")
        exp = want["verdict"] + (f"/{want['step']}" if want.get("step") else "")
        rows.append(
            f"{v['id']:<6} {'ok' if ok else 'DIFF':<6} reference {got:<11} vector {exp}"
        )
        out.append(
            {
                "id": v["id"],
                "title": v["title"],
                "description": v["description"],
                "now": v["now"],
                "tool": v["tool"],
                "args": v["args"],
                "args_json": v["args_json"],
                "policy": {},
                "params": {},
                "replay_state": None,
                "presentation": {"aat_chain": compacts, "aat_pop": pop},
                "expected": {"verdict": verdict, "step": step},
            }
        )
    print("\n".join(rows))
    checked = len(out)
    print(
        f"\nAAT -02 reference verifier: {checked - failed}/{checked} agree, "
        f"{len(suite['vectors']) - checked} skipped (tenuo {tenuo_commit(tenuo)[:12]})"
    )
    if write:
        doc = {
            "spec": "draft-niyikiza-oauth-attenuating-agent-tokens-02",
            "source": "PrivateVault's pv-delegation/2 scenarios (pv-delegation-2.json), built and "
            "verified with tenuo-ai/tenuo ietf/vectors/gen_vectors.py by "
            "tools/check_aat02_analogues.py",
            "reference_commit": tenuo_commit(tenuo),
            "conventions": {
                "keys": "Ed25519 seed = SHA-256('pv-aat02-analogues/' + name). Test keys only.",
                "expected": "The reference verifier's verdict and Section 8 step.",
            },
            "params": {
                k: getattr(g, k.upper())
                for k in (
                    "max_iat_skew",
                    "max_token_lifetime",
                    "max_delegation_depth",
                    "max_constraint_depth",
                    "max_token_size",
                    "max_chain_size",
                )
            }
            | {"pop_window": g.POP_WINDOW, "audience": g.AUDIENCE},
            "trust_anchors": [{"iss": iss, "jwk": jwk} for iss, jwk in b.trust],
            "vectors": out,
        }
        OUT.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {OUT.relative_to(ROOT)}: {len(out)} vectors")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--tenuo", default=os.environ.get("TENUO_DIR"), help="tenuo-ai/tenuo checkout"
    )
    p.add_argument(
        "--write", action="store_true", help=f"also write {OUT.relative_to(ROOT)}"
    )
    args = p.parse_args(argv)
    if not args.tenuo:
        p.error("pass --tenuo or set TENUO_DIR")
    return run(Path(args.tenuo), args.write)


if __name__ == "__main__":
    raise SystemExit(main())
