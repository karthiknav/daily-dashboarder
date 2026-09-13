# Daily Dashboard UI

A static, local dashboard for the JSON produced by `daily-dashboard scan` (`write_report()` in
`src/daily_dashboard/jobs/daily_scan.py`). It has no server, no build step and no external network
calls — everything runs from the files in this folder, opened directly in a browser.

## Open the dashboard

1. Double-click **index.html**.
2. Click **Load report JSON** and select the report file written by the daily scan job (e.g. `report.json`).
   To try the dashboard without running a real scan, select **sample-report.json** in this folder —
   it covers every field (a failed build, a scan error, ready and failed remediations, certificates
   at different urgency levels, announcements).
3. The dashboard renders from that file only. Reloading the page requires selecting the file again —
   a page opened via `file://` cannot read local files automatically.

## Pages

- **Overview** — KPI tiles aggregated across every pipeline: dependency-scanner violations,
  Checkmarx violations, failed pipeline builds, certificates expiring within 60 days, and
  announcements. Each tile links to its section.
- **Dependency Scanner** / **Checkmarx** — one row per pipeline with severity counts, sorted so the
  worst pipeline is first. Filter by severity or by "only pipelines with ready PRs". Click a row to
  expand it in place and see each individual finding, including a link to its pull request when the
  `remediation.prUrl` field is set (falls back to the remediation notes when there is no PR).
- **Pipelines** — latest build result per pipeline, sorted with failed builds first.
- **Certificates** — certificates expiring within 60 days by default (toggle "Show all" for the rest),
  sorted soonest-first and color-banded by days remaining.
- **Announcements** — a reverse-chronological list, if the report includes any.

## Report schema

The dashboard reads the exact shape produced by `run_daily_scan()`:

```jsonc
{
  "generatedAt": "...",
  "summary": { "totalPipelines": 0, "pipelinesFailed": 0, "totalViolations": 0, "violationsByCategory": {}, "violationsBySeverity": {}, "readyPrCount": 0, "certificatesExpiringSoon": 0, "unreadAnnouncements": 0 },
  "pipelines": [
    {
      "target": "...", "pipeline": "...", "project": "...",
      "buildId": 0, "buildNumber": "...", "buildUrl": "...",
      "buildResult": "succeeded|failed|partiallySucceeded|canceled",
      "buildFinishedAt": "...",
      "violationCounts": { "dependency_scanner": 0, "checkmarx": 0, "total": 0, "bySeverity": {} },
      "findings": [ { "category": "...", "severity": "...", "summary": "...", "finding": {}, "remediation": { "attempted": true, "success": true, "prUrl": null, "notes": null } } ]
    }
  ],
  "certificates": [ { "name": "...", "environment": "...", "expiresOn": "...", "expiresInDays": 0 } ],
  "announcements": [ { "id": "...", "subject": "...", "from": "...", "receivedAt": "...", "priority": "high|normal", "summary": "...", "link": null } ]
}
```

`announcements` is populated from Microsoft Graph mail when `load_graph_config()` finds Graph
credentials configured (see `_fetch_announcements()` in `daily_scan.py`); otherwise, and whenever the
Graph fetch fails, it stays an empty array and the fetch failure is logged rather than blocking the
scan. `certificates` is still an empty array until a certificate source is wired up. Either page
renders as an empty state when its array is empty, without needing further UI changes.

If loading a file fails (missing fields, invalid JSON), an error banner is shown and the previously
loaded report — if any — stays visible.

## Files

```text
ui/
  index.html
  README.md
  css/styles.css
  js/app.js            — view model + rendering for all pages
  js/data-loader.js     — reads and JSON-parses a user-selected local file
  js/charts.js          — donut/legend/bar/sparkline SVG renderers
  js/icons.js           — inline SVG icon set
  assets/favicon.svg
```
