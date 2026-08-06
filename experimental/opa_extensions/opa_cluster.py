"""
OPA Cluster Adapter — Multi-Endpoint Failover & Health Rotation.

Extends OPAPolicyAdapter with primary/secondary/DR endpoint support.
Matches docs/GLOBAL_DEPLOYMENT.md (multi-region deployment).
Does NOT replace single-endpoint adapter; complements it.
"""


class OPAClusterAdapter:
    """
    Multi-endpoint OPA connector with automatic failover.
    Health checks rotate to healthy endpoint.
    """

    def __init__(
        self,
        endpoints: list[str],
        health_check_interval: int = 10,
        preferred_region: str | None = None,
    ):
        self.endpoints = endpoints
        self.health_status = {ep: True for ep in endpoints}
        self.preferred_region = preferred_region
        self.current_active = endpoints[0] if endpoints else None
        self.health_check_interval = health_check_interval

    def health_check_all(self) -> dict[str, bool]:
        """
        Check health of all endpoints.
        In production: HTTP GET /health or /v1/data/system/info
        """
        # Stub: would call endpoint health checks
        return self.health_status

    def rotate_to_healthy(self) -> str | None:
        for ep in self.endpoints:
            if self.health_status.get(ep, False):
                self.current_active = ep
                return ep
        # No healthy endpoint: fallback to first
        self.current_active = self.endpoints[0] if self.endpoints else None
        return self.current_active

    def get_active_endpoint(self) -> str | None:
        return self.current_active

    def metrics_summary(self) -> dict:
        return {
            "adapter": "opa_cluster",
            "endpoints": self.endpoints,
            "active": self.current_active,
            "healthy_count": sum(self.health_status.values()),
            "region_preference": self.preferred_region,
        }
