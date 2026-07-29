# pvscan

Read-only inventory of what your AI coding agents can actually do.

One file, Python 3.12+, standard library only. No install, no
dependencies, no network. It reads the paths you give it and writes
nothing except the report you ask for.

## Run it

    python3 pvscan.py --dry-run ~/.claude/projects/     # list files, read none
    python3 pvscan.py ~/.claude/projects/               # the report
    python3 pvscan.py ~/.claude/projects/ --json out.json

Also reads Cursor sessions, MCP server logs, OpenAI and Anthropic
tool-call traces, generic JSONL and CSV. Format is detected; override
with `--format` when the answer matters.

## Check it before you run it

    grep -nE '^(import|from) ' pvscan.py     # stdlib only
    grep -n 'open(' pvscan.py                # every file touched
    grep -nE 'socket|urllib|request|http'    # returns nothing

There is no network code in this file and no telemetry. Nothing is
transmitted. The only write is the `--json` path, and only if you pass
one.

## What the report contains

**Effect distribution.** Every action classified IRREVERSIBLE, MUTATING,
UNKNOWN or READ_ONLY. Irreversible means re-running something will not
undo it: a force-push, a package publish, a recursive delete, an
outbound state-changing request.

**Tools observed.** Per capability, the spread of effects rather than one
label. `Bash` is not one thing -- `git status` and `git push --force`
arrive under the same name, so a single verdict would overstate it.

**Irreversible actions.** What they were and which session reached them.

**Reach by agent.** How many distinct tools each session touched and how
many irreversible actions it got to.

**Unclassified.** Capabilities the tool does not recognise. These are
reported as UNKNOWN, never assumed safe. Assuming an unrecognised tool
is harmless is the one error that would make the report worse than
useless.

**Authority evidence.** Expect zero. No mainstream agent framework emits
a record of the authority an action was taken under, so this measures
instrumentation across the industry rather than anything about your
setup. Nothing in the report shows an action was unauthorised -- only
that authorisation cannot be demonstrated either way.

## Known limits

Classification is by capability name and, for shell tools, by the
command string. It is pattern matching, not semantic analysis. It will
miss things and it will occasionally over-flag. A command built at
runtime from variables reads as UNKNOWN, which is the correct failure
direction but still a gap.

Coverage is reported verbatim. A scan that only understood 60% of your
log is worth 60% as much and the report says so rather than quietly
dropping the rest.

Session identity comes from `sessionId`. In Claude Code one session is
one agent, so "agents" in the report means sessions.

## What is useful back

Not the report -- what broke. Lines it could not parse, formats it did
not recognise, assumptions about your logs that were wrong, anything
that looked wrong in the output.

    python3 pvscan.py <path> --dry-run     # confirms which files it found

If the parser chokes, ten redacted lines of the offending format is
enough to fix it.

---

PrivateVault AI -- privatevault.ai
