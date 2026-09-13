# daily-dashboard

Agentic daily scan of Azure DevOps pipelines for operational issues. v1 covers:

- Dependency Scanner / Vulnerability issues
- Checkmarx violations
- Announcements: recent mail from a configured mailbox (Microsoft Graph),
  LLM-summarized to 1-2 lines each

For each finding, the tool clones the affected repo, creates a branch, uses an
LLM (Azure OpenAI Chat Completions API with tool-calling, same pattern as
[yapl-upgrader](../yapl-upgrader)'s `core/rewrite_runner.py`) to apply a fix,
and opens a Pull Request for human review via `core/ado_git.py` (vendored from
yapl-upgrader).

Other categories from the original scope (expiring certificates, incidents,
environment health checks) are intentionally out of scope for v1 - see the
plan this project was scaffolded from.

## Setup

```
pip install -e .
cp .env.example .env   # fill in ADO_ORG_URL, ADO_PAT, AZURE_OPENAI_*
cp pipelines.example.yml pipelines.yml   # list the repos/pipelines to scan
```

Announcements are optional: the scan runs with an empty announcements list
unless `MS_GRAPH_TENANT_ID`, `MS_GRAPH_CLIENT_ID`, `MS_GRAPH_CLIENT_SECRET`
and `MS_GRAPH_MAILBOX` are set (see `.env.example`). The Graph app
registration needs the *application* (not delegated) `Mail.Read` permission,
admin-consented and scoped to `MS_GRAPH_MAILBOX` via an application access
policy. `ANNOUNCEMENTS_LOOKBACK_HOURS` (default `24`) controls how far back
`core/ms_graph.py` looks for new mail.

## Usage

```
daily-dashboard scan --config pipelines.yml --dry-run   # report findings only
daily-dashboard scan --config pipelines.yml              # create branches/PRs
```

## Open items

- The exact report/log format emitted by this org's dependency-scan and
  Checkmarx ADO tasks hasn't been confirmed against a real pipeline run.
  `scanners/dependency_scanner.py` and `scanners/checkmarx_scanner.py`
  currently support a generic pre-normalized JSON list plus one well-known
  public format each (OWASP Dependency-Check JSON, SARIF) - extend with an
  org-specific parser once real task output is inspected.
- Whether this project needs its own Azure OpenAI deployment or reuses
  yapl-upgrader's.

## Tests

```
pytest
```
