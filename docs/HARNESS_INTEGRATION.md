# Agent Harness Integration

PrivateVault Agent DNA connects to any agent harness (Anthropic Agent Harness, CrewAI, AutoGen, custom) through the adapter layer.

## Skill Manifest (`skills.json`)

Each agent exports a capability manifest:

```json
{
  "agent_id": "code-agent-01",
  "allowed_capabilities": [
    "git.read_repo", "git.create_pr", "test.run_unit"
  ],
  "denied_capabilities": [
    "deploy.production", "storage.bulk_export"
  ]
}
