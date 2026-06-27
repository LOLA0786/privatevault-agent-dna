"""
Enterprise Change Management Importers.

Every imported approval is persisted into the shared GrantStore via
AuthorizationPolicy.
"""

from __future__ import annotations

from typing import Any, Dict

from .authorization import AuthorizationPolicy


class ChangeManagementImporter:

    def __init__(
        self,
        policy: AuthorizationPolicy | None = None,
    ) -> None:

        self.policy = policy or AuthorizationPolicy()

    # ---------------------------------------------------------
    # Generic
    # ---------------------------------------------------------

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
            version=record.get(
                "version",
                "*",
            ),
            expires_at=record.get(
                "expires_at",
            ),
        )

    # ---------------------------------------------------------
    # ServiceNow
    # ---------------------------------------------------------

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
                "version": record.get(
                    "version",
                    "*",
                ),
            }
        )

    # ---------------------------------------------------------
    # Jira
    # ---------------------------------------------------------

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
                "version": issue.get(
                    "version",
                    "*",
                ),
            }
        )
