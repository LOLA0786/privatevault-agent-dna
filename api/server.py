"""
PrivateVault Agent DNA API
"""

from fastapi import FastAPI

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    DriftScorer,
    FingerprintBuilder,
    ProfileDiffEngine,
    SimilarityEngine,
    BehaviorTimeline,
)

from agent_dna.adapters import (
    synthetic_normal_trace,
    synthetic_compromised_trace,
)

app = FastAPI(
    title="PrivateVault Agent DNA",
    version="0.1.0",
)

training = [
    synthetic_normal_trace(seed=i, loops=6)
    for i in range(8)
]

manifold = CapabilityManifold().fit(training)
dynamics = BehaviorDynamics().fit(training)

scorer = DriftScorer(
    manifold,
    dynamics,
)

builder = FingerprintBuilder()
similarity = SimilarityEngine()
diff_engine = ProfileDiffEngine()


@app.get("/")
def root():
    return {
        "product": "PrivateVault Agent DNA",
        "category": "Behavioral Identity Platform",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


@app.get("/fingerprint")
def fingerprint():

    fp = builder.build(
        "sales-agent-01",
        manifold,
        dynamics,
    )

    return fp.to_dict()


@app.get("/compare")
def compare():

    trusted = builder.build(
        "sales-agent-01",
        manifold,
        dynamics,
    )

    candidate = builder.build(
        "sales-agent-01",
        CapabilityManifold().fit(
            [synthetic_compromised_trace()]
        ),
        BehaviorDynamics().fit(
            [synthetic_compromised_trace()]
        ),
    )

    return similarity.compare(
        trusted,
        candidate,
    ).to_dict()


@app.get("/diff")
def diff():

    trusted = builder.build(
        "sales-agent-01",
        manifold,
        dynamics,
    )

    candidate = builder.build(
        "sales-agent-01",
        CapabilityManifold().fit(
            [synthetic_compromised_trace()]
        ),
        BehaviorDynamics().fit(
            [synthetic_compromised_trace()]
        ),
    )

    report = diff_engine.diff(
        trusted,
        candidate,
    )

    return report.__dict__


@app.get("/timeline")
def timeline():

    timeline = BehaviorTimeline()

    timeline.add(
        "v1",
        builder.build(
            "sales-agent-01",
            manifold,
            dynamics,
        ),
    )

    timeline.add(
        "v2",
        builder.build(
            "sales-agent-01",
            CapabilityManifold().fit(
                [synthetic_compromised_trace()]
            ),
            BehaviorDynamics().fit(
                [synthetic_compromised_trace()]
            ),
        ),
    )

    return {
        "versions": timeline.versions(),
        "stability": timeline.stability_score(),
    }
