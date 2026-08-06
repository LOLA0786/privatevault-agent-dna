"""
Enterprise Change Management Demo.

Simulates importing approved capability changes from enterprise
change-management systems.
"""

from agent_dna import (
    AuthorizationPolicy,
    ChangeManagementImporter,
)

policy = AuthorizationPolicy()

importer = ChangeManagementImporter(policy)


print("\n==========================================")
print("ServiceNow Import")
print("==========================================")

importer.import_servicenow(
    {
        "agent_id": "sales-agent-01",
        "capability": "payments.initiate_wire",
        "requested_by": "Operations",
        "change_number": "CHG-20481",
        "environment": "prod",
    }
)

print(
    policy.lookup(
        "sales-agent-01",
        "payments.initiate_wire",
    )
)


print("\n==========================================")
print("Jira Import")
print("==========================================")

importer.import_jira(
    {
        "agent_id": "sales-agent-01",
        "capability": "storage.bulk_export",
        "assignee": "Security Team",
        "key": "OPS-842",
        "environment": "prod",
    }
)

print(
    policy.lookup(
        "sales-agent-01",
        "storage.bulk_export",
    )
)
