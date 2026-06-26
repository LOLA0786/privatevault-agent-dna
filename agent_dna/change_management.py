"""
Enterprise Change Management Adapters.

These adapters convert approved enterprise change records into
AuthorizationPolicy grants.

Initially supports generic dicts.

Later adapters can be added for:

- ServiceNow
- Jira
- GitHub Releases
- Azure DevOps
- PagerDuty
- Internal CAB systems
"""

from __future__ import annotations

from typing import Dict, Any

from .authorization import AuthorizationPolicy


class ChangeManagementImporter:

    def __init__(
        self,
        policy: AuthorizationPolicy,
    ) -> None:
        self.policy = policy

    # ----------------------------------------------------------
    # Generic JSON import
    # ----------------------------------------------------------

    def import_change(
        self,
        record: Dict[str, Any],
    ) -> None:

        self.policy.grant(
            agent_id=record["agent_id"],
            capability=record["capability"],
            approved_by=record["approved_by"],
            ticket=record["ticket"],
            environment=record.get(
                "environment",
                "prod",
            ),
            expires_at=record.get(
                "expires_at",
            ),
        )

    # ----------------------------------------------------------
    # ServiceNow
    # ----------------------------------------------------------

    def import_servicenow(
        self,
        record: Dict[str, Any],
    ) -> None:

        self.import_change(
            {
                "agent_id": record["agent_id"],
                "capability": record["capability"],
                "approved_by": record["requested_by"],
                "ticket": record["change_number"],
                "environment": record.get(
                    "environment",
                    "prod",
                ),
            }
        )

    # ----------------------------------------------------------
    # Jira
    # ----------------------------------------------------------

    def import_jira(
        self,
        issue: Dict[str, Any],
    ) -> None:

        self.import_change(
            {
                "agent_id": issue["agent_id"],
                "capability": issue["capability"],
                "approved_by": issue["assignee"],
                "ticket": issue["key"],
                "environment": issue.get(
                    "environment",
                    "prod",
                ),
            }
        )
