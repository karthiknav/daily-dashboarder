/* Charts read application/json from HTML; scanner records can also come from a backend daily-scan report JSON. */
(function () {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const C = window.DashboardCharts;
  const E = C.escape;
  const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'unknown'];
  const SEVERITY_COLORS = {
    critical: '#f13e40',
    high: '#ff8610',
    medium: '#ffd025',
    low: '#31db78',
    unknown: '#5d6e82'
  };

  let snapshot = null;
  let scannerReport = null;
  let backendView = null;
  let busy = false;
  let toastTimer;
  let sourceName = '';
  let backendSourceName = '';
  let activeNavigation = 'operations-wall';

  const severityClass = severity => {
    const key = normalizeSeverity(severity);
    return ({
      critical: 'danger',
      high: 'warning',
      medium: 'medium',
      low: 'good',
      unknown: 'muted'
    }[key] || 'muted');
  };

  function icon(name) { return window.Icons.svg(name); }
  document.querySelectorAll('[data-icon]').forEach(element => { element.innerHTML = icon(element.dataset.icon); });

  function normalizeSeverity(value) {
    const text = String(value || '').trim().toLowerCase();
    if (!text) return 'unknown';
    if (text === 'critical') return 'critical';
    if (text === 'high' || text === 'error') return 'high';
    if (text === 'medium' || text === 'warning') return 'medium';
    if (text === 'low' || text === 'note' || text === 'info') return 'low';
    return 'unknown';
  }

  function severityLabel(key) {
    return ({ critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown' }[key] || 'Unknown');
  }

  function categoryKey(value) {
    const text = String(value || '').trim().toLowerCase();
    if (text.includes('checkmarx')) return 'checkmarx';
    if (text.includes('depend')) return 'dependency_scanner';
    return text || 'other';
  }

  function categoryLabel(value) {
    if (value === 'dependency_scanner') return 'Dependency Scanner';
    if (value === 'checkmarx') return 'Checkmarx';
    return value.replace(/_/g, ' ');
  }

  function ensureSeverityCounts() {
    return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  }

  function severityRows(counts) {
    return SEVERITY_KEYS.map(key => ({
      label: severityLabel(key),
      value: counts[key] || 0,
      color: SEVERITY_COLORS[key]
    }));
  }

  function validateBackendReport(data) {
    const require = (ok, message) => { if (!ok) throw new Error(`Invalid backend report: ${message}`); };
    require(data && typeof data === 'object', 'root must be a JSON object.');
    require(Array.isArray(data.pipelines), 'pipelines must be an array.');
    data.pipelines.forEach((entry, index) => {
      require(entry && typeof entry === 'object', `pipelines[${index}] must be an object.`);
      if (!entry.error) require(Array.isArray(entry.findings), `pipelines[${index}].findings must be an array when no error is present.`);
    });
    return data;
  }

  function summaryText(finding) {
    if (finding.summary) return String(finding.summary);
    const payload = finding.finding || {};
    const packageName = payload.package || payload.name;
    if (packageName) return `${packageName} ${payload.currentVersion || ''}`.trim();
    if (payload.rule || payload.file) return `${payload.rule || 'Rule'} in ${payload.file || 'unknown file'}`;
    return 'Finding';
  }

  function buildBackendView(report) {
    const globalSeverity = ensureSeverityCounts();
    const categories = {};
    const pipelines = [];
    const dependencyFindings = [];
    const checkmarxFindings = [];
    let totalViolations = 0;
    let readyPrCount = 0;

    (report.pipelines || []).forEach((pipeline, index) => {
      if (pipeline.error) return;

      const pipelineName = pipeline.pipeline || pipeline.target || `Pipeline ${index + 1}`;
      const pipelineEntry = {
        name: pipelineName,
        target: pipeline.target || pipelineName,
        project: pipeline.project || '',
        buildNumber: pipeline.buildNumber || '',
        buildUrl: pipeline.buildUrl || '',
        counts: { total: 0, dependency_scanner: 0, checkmarx: 0 },
        severityCounts: ensureSeverityCounts(),
        findings: []
      };

      (pipeline.findings || []).forEach(entry => {
        const key = categoryKey(entry.category);
        const sevKey = normalizeSeverity(entry.severity || (entry.finding || {}).severity);
        const remediation = entry.remediation || {};
        const normalized = {
          pipeline: pipelineName,
          categoryKey: key,
          category: categoryLabel(key),
          severityKey: sevKey,
          severity: severityLabel(sevKey),
          summary: summaryText(entry),
          finding: entry.finding || {},
          remediation,
          buildUrl: pipeline.buildUrl || ''
        };

        pipelineEntry.findings.push(normalized);
        pipelineEntry.counts.total += 1;
        pipelineEntry.counts[key] = (pipelineEntry.counts[key] || 0) + 1;
        pipelineEntry.severityCounts[sevKey] += 1;

        categories[key] = (categories[key] || 0) + 1;
        globalSeverity[sevKey] += 1;
        totalViolations += 1;
        if (remediation.prUrl) readyPrCount += 1;

        if (key === 'dependency_scanner') {
          dependencyFindings.push(normalized);
        } else if (key === 'checkmarx') {
          checkmarxFindings.push(normalized);
        }
      });

      pipelines.push(pipelineEntry);
    });

    pipelines.sort((a, b) => b.counts.total - a.counts.total);

    const packageMap = new Map();
    dependencyFindings.forEach(item => {
      const payload = item.finding;
      const name = payload.package || 'unknown-package';
      const version = payload.currentVersion || 'unknown-version';
      const identity = `${name}@${version}`;
      if (!packageMap.has(identity)) {
        packageMap.set(identity, {
          name,
          version,
          pipelines: new Set(),
          highestSeverity: item.severityKey
        });
      }
      const current = packageMap.get(identity);
      current.pipelines.add(item.pipeline);
      if (SEVERITY_KEYS.indexOf(item.severityKey) < SEVERITY_KEYS.indexOf(current.highestSeverity)) {
        current.highestSeverity = item.severityKey;
      }
    });

    const dependencyPackages = Array.from(packageMap.values())
      .map(item => ({
        name: item.name,
        version: item.version,
        pipelines: Array.from(item.pipelines),
        highestSeverity: item.highestSeverity
      }))
      .sort((a, b) => b.pipelines.length - a.pipelines.length);

    const categoryRows = Object.keys(categories).map(key => ({
      label: categoryLabel(key),
      value: categories[key],
      color: key === 'checkmarx' ? '#36aa50' : '#ff8c21'
    }));

    return {
      generatedAt: report.generatedAt,
      totals: {
        pipelines: pipelines.length,
        violations: totalViolations,
        readyPrCount: Number.isFinite(report.summary?.readyPrCount) ? report.summary.readyPrCount : readyPrCount
      },
      categories: categoryRows,
      severity: severityRows(globalSeverity),
      scanners: {
        dependency: {
          total: dependencyFindings.length,
          severity: severityRows(dependencyFindings.reduce((acc, item) => {
            acc[item.severityKey] += 1;
            return acc;
          }, ensureSeverityCounts())),
          findings: dependencyFindings,
          packages: dependencyPackages
        },
        checkmarx: {
          total: checkmarxFindings.length,
          severity: severityRows(checkmarxFindings.reduce((acc, item) => {
            acc[item.severityKey] += 1;
            return acc;
          }, ensureSeverityCounts())),
          findings: checkmarxFindings
        }
      },
      pipelines
    };
  }

  // Validate before rendering so a malformed edit produces a useful message.
  function validate(data) {
    const require = (ok, message) => { if (!ok) throw new Error(`Invalid dashboard data: ${message}`); };
    const count = value => Number.isFinite(value) && value >= 0;
    const color = value => typeof value === 'string' && /^#[a-f0-9]{6}$/i.test(value);
    const rows = (items, label) => {
      require(Array.isArray(items), `${label} must be an array.`);
      items.forEach(row => require(typeof row.label === 'string' && count(row.value) && color(row.color), `${label} requires label, non-negative value and a six-digit hex color.`));
    };
    require(data && data.meta?.schemaVersion === 1, 'schemaVersion must be 1.');
    require(!Number.isNaN(Date.parse(data.meta.snapshotAt)), 'meta.snapshotAt must be an ISO date.');
    require(typeof data.meta.user?.name === 'string' && typeof data.meta.user?.role === 'string', 'meta.user requires name and role.');
    require(Array.isArray(data.kpis) && data.kpis.length > 0, 'provide KPI cards in display order.');
    data.kpis.forEach(k => require(typeof k.title === 'string' && count(k.value) && color(k.color) && typeof k.label === 'string', 'each KPI requires title, value, label and color.'));
    rows(data.pipeline?.summary, 'pipeline.summary');
    rows(data.incidents?.severity, 'incidents.severity');
    rows(data.vulnerabilities?.severity, 'vulnerabilities.severity');
    require(Array.isArray(data.pipeline.daily?.labels) && Array.isArray(data.pipeline.daily?.series), 'pipeline.daily requires labels and series arrays.');
    data.pipeline.daily.series.forEach(s => require(typeof s.label === 'string' && color(s.color) && Array.isArray(s.values) && s.values.length === data.pipeline.daily.labels.length && s.values.every(count), 'daily series must have non-negative values matching labels, and a hex color.'));
    require(Array.isArray(data.environments), 'environments must be an array.');
    data.environments.forEach(e => require(typeof e.name === 'string' && typeof e.status === 'string' && count(e.healthScore) && e.healthScore <= 100 && Array.isArray(e.trend) && e.trend.every(v=>count(v)&&v<=100), 'each environment requires name, status, healthScore and numeric trend values from 0-100.'));
    require(Array.isArray(data.vulnerabilities.top), 'vulnerabilities.top must be an array.');
    data.vulnerabilities.top.forEach(v => require(typeof v.title === 'string' && typeof v.severity === 'string', 'top vulnerabilities require title and severity.'));
    require(Array.isArray(data.certificates), 'certificates must be an array.');
    data.certificates.forEach(c => require(typeof c.name === 'string' && typeof c.environment === 'string' && Number.isFinite(c.expiresInDays), 'certificates require name, environment and numeric expiresInDays.'));
    require(Array.isArray(data.navigation) && Array.isArray(data.integrations), 'navigation and integrations must be arrays.');
    data.navigation.forEach(n=>require(typeof n.label==='string' && /^[a-z-]+$/.test(n.target), 'navigation requires label and a lowercase target.'));
    data.integrations.forEach(i=>require(typeof i.name==='string' && typeof i.description==='string' && color(i.color), 'integrations require name, description and color.'));
    require(data.menuContent && typeof data.menuContent==='object', 'menuContent must be an object.');
    Object.values(data.menuContent).forEach(m=>require(typeof m.title==='string' && typeof m.description==='string' && Array.isArray(m.items), 'menu content requires title, description and items.'));
    require(data.kpis[0].source === 'scanner', 'the first KPI must use source scanner.');
    require(data.healthRules && typeof data.healthRules.healthyStatus === 'string', 'healthRules requires healthyStatus.');
    require(count(data.healthRules.certificateWarningDays) && count(data.healthRules.certificateCriticalDays) && data.healthRules.certificateCriticalDays <= data.healthRules.certificateWarningDays, 'certificate thresholds must be valid non-negative numbers.');
    require(data.ui && typeof data.ui.title === 'string' && typeof data.ui.subtitle === 'string', 'ui requires title and subtitle.');
    ['team', 'assistantName', 'assistantStatus', 'assistantButton', 'integrationCaption'].forEach(key => require(typeof data.ui[key] === 'string', `ui.${key} must be text.`));
    const panelIds = ['pipeline-title', 'incidents-title', 'environment-title', 'vulnerability-title', 'top-vulnerability-title', 'certificate-title'];
    require(Array.isArray(data.ui.panels) && panelIds.every(id => data.ui.panels.some(p => p.id === id)), 'ui.panels must define all six panel headings.');
    data.ui.panels.forEach(p => require(panelIds.includes(p.id) && typeof p.title === 'string' && typeof p.subtitle === 'string' && typeof p.link === 'string' && /^[a-z-]+$/.test(p.detail), 'panel labels are invalid.'));
    require(data.ui.tables && data.ui.charts, 'ui requires tables and charts.');
    ['environment', 'certificate', 'summary'].forEach(key => require(Array.isArray(data.ui.tables[key]) && data.ui.tables[key].every(v => typeof v === 'string'), `ui.tables.${key} must be an array of text.`));
    ['pipelineTotal', 'total', 'pipelineBars', 'vulnerabilityBars'].forEach(key => require(typeof data.ui.charts[key] === 'string', `ui.charts.${key} must be text.`));
    return data;
  }

  function kpiValue(kpi) {
    if (kpi.source === 'scanner') {
      if (backendView) return backendView.scanners.dependency.total;
      return scannerReport ? scannerReport.dependencyCount : '-';
    }
    if (kpi.source === 'incidents') return C.total(snapshot.incidents.severity);
    if (kpi.source === 'vulnerabilities') return C.total(snapshot.vulnerabilities.severity);
    if (kpi.source === 'certificates') return snapshot.certificates.filter(c => c.expiresInDays <= snapshot.healthRules.certificateWarningDays).length;
    return kpi.value;
  }

  function table(headers, rows, className) {
    const klass = className || '';
    return `<table class="${klass}"><thead><tr>${headers.map(h=>`<th scope="col">${E(h)}</th>`).join('')}</tr></thead><tbody>${rows.length ? rows.map(row=>`<tr>${row.map(cell=>`<td>${cell}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${headers.length}" class="muted">No records available.</td></tr>`}</tbody></table>`;
  }

  function environmentTable() {
    return table(snapshot.ui.tables.environment, snapshot.environments.map(e=>[
      E(e.name), `<span class="health-score ${severityClass(e.status)}">${e.healthScore.toFixed(1)}%</span>`,
      `<span class="${severityClass(e.status)}">${E(e.status)}</span>`, C.sparkline(e.trend, e.status === 'Healthy' ? '#3ce989' : '#ff9800')
    ]), 'health-table');
  }

  function certificateTable() {
    return table(snapshot.ui.tables.certificate, snapshot.certificates.map(c=>[
      E(c.name), E(c.environment), `<span class="${c.expiresInDays <= snapshot.healthRules.certificateCriticalDays ? 'danger' : c.expiresInDays <= snapshot.healthRules.certificateWarningDays ? 'warning' : 'good'}">${c.expiresInDays < 0 ? `${Math.abs(c.expiresInDays)} days overdue` : `${c.expiresInDays} days`}</span>`
    ]));
  }

  function topVulnerabilityTable() {
    const items = snapshot.vulnerabilities.top;
    return `<table aria-label="Top vulnerability findings"><tbody>${items.length ? items.map((v, i)=>`<tr><td><span class="rank">${i + 1}</span>${E(v.title)}</td><td class="${severityClass(v.severity)}">${E(v.severity)}</td></tr>`).join('') : '<tr><td class="muted">No vulnerabilities listed.</td></tr>'}</tbody></table>`;
  }

  function backendDependencyRows(compact) {
    if (!backendView) return '';
    return backendView.scanners.dependency.packages.slice(0, compact ? 8 : 30).map(item => {
      return `<div class="${compact ? 'scanner-dependency-row' : 'scanner-finding'}"><strong>${E(item.name)}</strong><span class="dependency-coordinates">Version: ${E(item.version)} · Pipelines: ${E(item.pipelines.join(', '))}</span></div>`;
    }).join('');
  }

  function renderBackendSections() {
    const depRoot = $('#dependency-scanner-content');
    const cxRoot = $('#checkmarx-content');
    const pipeRoot = $('#pipeline-findings-content');
    if (!depRoot || !cxRoot || !pipeRoot) return;

    if (!backendView) {
      depRoot.innerHTML = '<p class="scanner-empty">Load backend report JSON to visualize dependency findings across pipelines.</p>';
      cxRoot.innerHTML = '<p class="scanner-empty">Load backend report JSON to visualize Checkmarx findings across pipelines.</p>';
      pipeRoot.innerHTML = '<p class="scanner-empty">Load backend report JSON to list pipeline-by-pipeline findings.</p>';
      return;
    }

    const dep = backendView.scanners.dependency;
    const cx = backendView.scanners.checkmarx;

    depRoot.innerHTML = `<div class="scanner-section-summary">${C.donut(dep.severity, 'Findings')}${C.legend(dep.severity, true)}</div><div class="table-wrap">${table(['Pipeline', 'Package', 'Version', 'Severity', 'CVE', 'PR'], dep.findings.slice(0, 20).map(item => {
      const payload = item.finding;
      const pr = item.remediation.prUrl ? `<a href="${E(item.remediation.prUrl)}" target="_blank" rel="noopener noreferrer">PR</a>` : '-';
      return [
        E(item.pipeline),
        E(payload.package || payload.name || '-'),
        E(payload.currentVersion || '-'),
        `<span class="${severityClass(item.severity)}">${E(item.severity)}</span>`,
        E(payload.cve || '-'),
        pr
      ];
    }))}</div>`;

    cxRoot.innerHTML = `<div class="scanner-section-summary">${C.donut(cx.severity, 'Findings')}${C.legend(cx.severity, true)}</div><div class="table-wrap">${table(['Pipeline', 'Rule', 'File', 'Severity', 'PR'], cx.findings.slice(0, 20).map(item => {
      const payload = item.finding;
      const pr = item.remediation.prUrl ? `<a href="${E(item.remediation.prUrl)}" target="_blank" rel="noopener noreferrer">PR</a>` : '-';
      return [
        E(item.pipeline),
        E(payload.rule || '-'),
        E(payload.file || '-'),
        `<span class="${severityClass(item.severity)}">${E(item.severity)}</span>`,
        pr
      ];
    }))}</div>`;

    const pipelineRows = backendView.pipelines.map(item => {
      const build = item.buildUrl ? `<a href="${E(item.buildUrl)}" target="_blank" rel="noopener noreferrer">${E(item.buildNumber || 'Build')}</a>` : E(item.buildNumber || '-');
      return [
        E(item.name),
        E(item.project || '-'),
        build,
        String(item.counts.dependency_scanner || 0),
        String(item.counts.checkmarx || 0),
        String(item.counts.total)
      ];
    });

    const findingRows = backendView.pipelines.flatMap(item => item.findings.map(finding => [
      E(item.name),
      E(finding.category),
      `<span class="${severityClass(finding.severity)}">${E(finding.severity)}</span>`,
      E(finding.summary),
      finding.remediation.prUrl ? `<a href="${E(finding.remediation.prUrl)}" target="_blank" rel="noopener noreferrer">PR</a>` : E(finding.remediation.notes || '-')
    ])).slice(0, 40);

    pipeRoot.innerHTML = `<h3>Pipeline Summary</h3><div class="table-wrap">${table(['Pipeline', 'Project', 'Build', 'Dependency', 'Checkmarx', 'Total'], pipelineRows)}</div><h3>Top Findings</h3><div class="table-wrap">${table(['Pipeline', 'Scanner', 'Severity', 'Summary', 'Remediation'], findingRows)}</div>`;
  }

  function render() {
    document.title = snapshot.ui.title;
    $('.brand h1').textContent = snapshot.ui.title;
    $('.brand .subtitle').textContent = backendSourceName ? `Backend report: ${backendSourceName}` : snapshot.ui.subtitle;
    $('#team-select').options[0].textContent = snapshot.ui.team;
    $('#assistant-name').textContent = snapshot.ui.assistantName;
    $('#assistant-status').textContent = snapshot.ui.assistantStatus;
    $('#assistant-button-label').textContent = snapshot.ui.assistantButton;
    $('#severity-heading').textContent = snapshot.ui.tables.vulnerabilitySeverity;
    snapshot.ui.panels.forEach(panel => {
      document.getElementById(panel.id).innerHTML = `${E(panel.title)}${panel.subtitle ? ` <small>${E(panel.subtitle)}</small>` : ''}`;
      document.querySelectorAll(`[data-detail="${panel.detail}"]`).forEach(button => { button.innerHTML = `${E(panel.link)} <span>-></span>`; });
    });
    $('#user-name').textContent = snapshot.meta.user.name;
    $('#user-role').textContent = snapshot.meta.user.role;

    const dateSource = backendView?.generatedAt || snapshot.meta.snapshotAt;
    const date = new Date(dateSource);
    $('#snapshot-time').dateTime = dateSource;
    $('#snapshot-time').textContent = `${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}  |  ${date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true, timeZone: 'UTC' })}`;
    $('#snapshot-time').title = backendView ? `Snapshot time (UTC) from backend report: ${backendSourceName}` : 'Snapshot time (UTC), read from the embedded dashboard-data JSON block';
    $('#notification-count').textContent = backendView ? String(backendView.totals.violations) : String(snapshot.kpis.find(k => k.id === 'critical-issues')?.value || 0);

    renderKpis();
    $('#side-nav').innerHTML = snapshot.navigation.map(n=>`<button class="nav-item ${n.target === activeNavigation ? 'active' : ''}" data-nav="${E(n.target)}" ${n.target === activeNavigation ? 'aria-current="page"' : ''}>${icon(n.icon)}<span>${E(n.label)}</span></button>`).join('');
    const daily = snapshot.pipeline.daily;
    $('#pipeline-content').innerHTML = `<div class="pipeline-summary">${C.donut(snapshot.pipeline.summary, snapshot.ui.charts.pipelineTotal)}${C.legend(snapshot.pipeline.summary)}</div>${C.bars(daily.labels, daily.series, { maximum: Math.max(40, ...daily.labels.map((_, i)=>daily.series.reduce((s, r)=>s + r.values[i], 0))), label: snapshot.ui.charts.pipelineBars })}`;
    $('#incidents-content').innerHTML = C.donut(snapshot.incidents.severity, snapshot.ui.charts.total) + C.legend(snapshot.incidents.severity);
    $('#environment-content').innerHTML = environmentTable();
    const vulnerabilities = snapshot.vulnerabilities.severity;
    $('#vulnerability-content').innerHTML = `<div class="vulnerability-summary">${C.donut(vulnerabilities, snapshot.ui.charts.total)}${C.legend(vulnerabilities, true)}</div>${C.bars(vulnerabilities.map(v=>v.label), [{ label: 'Vulnerabilities', colors: vulnerabilities.map(v=>v.color), values: vulnerabilities.map(v=>v.value) }], { maximum: Math.max(20, ...vulnerabilities.map(v=>v.value)), valueLabels: true, label: snapshot.ui.charts.vulnerabilityBars })}`;
    $('#top-vulnerability-content').innerHTML = topVulnerabilityTable();
    $('#certificate-content').innerHTML = certificateTable();
    renderBackendSections();
    $('#integration-caption').textContent = snapshot.ui.integrationCaption.replace('{count}', String(snapshot.integrations.length));
    $('#integration-caption').title = 'Demo data: no external accounts are connected.';
    $('#integrations').innerHTML = snapshot.integrations.slice(0, 9).map((integration, index)=>`<button class="integration" data-integration="${index}"><span class="integration-symbol" style="--logo-color:${E(integration.color)}">${icon(integration.icon)}</span>${E(integration.name)}</button>`).join('') + (snapshot.integrations.length > 9 ? `<button class="more-integrations" data-action="integrations">+ ${snapshot.integrations.length - 9} more</button>` : '');
    $('#loading').hidden = true;
    document.body.classList.add('data-loaded');
  }

  function dependencyRows(dependencies, compact) {
    return dependencies.map(d => `<div class="${compact ? 'scanner-dependency-row' : 'scanner-finding'}"><strong>${E(d.name)}</strong><span class="dependency-coordinates">${E(d.coordinates)} · Versions: ${E(d.versions.join(', '))}</span>${!compact && d.advisories.length ? `<div>${d.advisories.map(a => `<span class="scanner-tag ${severityClass(a.severity)}">${E(a.id)} · ${E(a.severity)}</span>`).join('')}</div>` : ''}</div>`).join('');
  }

  function renderKpis() {
    $('#kpis').innerHTML = snapshot.kpis.map(k => {
      if (k.source === 'scanner') {
        const title = scannerReport?.title || (backendView ? 'Dependency Scanner (Backend)' : k.title);
        const scannerBody = scannerReport
          ? `<div class="scanner-dependencies">${scannerReport.dependencies.length ? dependencyRows(scannerReport.dependencies, true) : '<p class="scanner-note">No dependencies in the selected JSON.</p>'}</div>`
          : backendView
            ? `<div class="scanner-dependencies">${backendView.scanners.dependency.packages.length ? backendDependencyRows(true) : '<p class="scanner-note">No dependency findings in backend report.</p>'}</div>`
            : '<p class="scanner-empty">Load backend report JSON to display findings by scanner and pipeline.</p>';

        return `<article class="kpi-card scanner-kpi" style="--accent:${E(k.color)}"><h2 class="kpi-title">${E(title)}</h2><button class="scanner-summary" data-action="scanner"><span class="kpi-art">${icon(k.icon)}</span><span><span class="kpi-number">${kpiValue(k)}</span><span class="kpi-label">${E(k.label)}</span></span></button>${scannerBody}<button class="scanner-load-button" data-action="choose-backend-json">${backendView ? 'Change Backend Report' : 'Load Backend Report'}</button></article>`;
      }

      return `<article class="kpi-card" style="--accent:${E(k.color)}"><h2 class="kpi-title">${E(k.title)}</h2><div class="kpi-body"><span class="kpi-art">${icon(k.icon)}</span><div><div class="kpi-number">${kpiValue(k)}</div><div class="kpi-label">${E(k.label)}</div></div></div>${k.change ? `<div class="kpi-change"><span class="delta">${E(k.change.arrow)} ${E(k.change.value)}</span> ${E(k.change.suffix)}</div>` : ''}</article>`;
    }).join('');
  }

  function loadEmbedded(manual) {
    const trigger = Boolean(manual);
    try {
      const data = JSON.parse($('#dashboard-data').textContent);
      snapshot = validate(data);
      render();
      $('#error-banner').hidden = true;
      if (trigger) toast('Charts reloaded from the JSON embedded in the HTML.');
    } catch (error) {
      $('#error-banner').hidden = false;
      $('#error-banner').textContent = `The chart data embedded in the HTML is invalid: ${error.message}`;
    }
  }

  function chooseFile() {
    if (busy) return;
    $('#scanner-file').value = '';
    $('#scanner-file').click();
  }

  function chooseBackendFile() {
    if (busy) return;
    $('#backend-report-file').value = '';
    $('#backend-report-file').click();
  }

  async function loadBackendReport(file) {
    if (busy || !file) return;
    busy = true;
    try {
      const data = await window.DashboardDataLoader.load(file);
      backendView = buildBackendView(validateBackendReport(data));
      backendSourceName = file.name;
      if (snapshot) render();
      $('#scanner-error').hidden = true;
      toast(`Backend report loaded: ${backendView.totals.violations} findings across ${backendView.totals.pipelines} pipelines.`);
    } catch (error) {
      $('#scanner-error').hidden = false;
      $('#scanner-error').innerHTML = `${E(error.message)} <button data-action="choose-backend-json">Select backend report JSON</button>`;
    } finally {
      busy = false;
    }
  }

  async function loadScanner(file) {
    if (busy || !file) return;
    busy = true;
    try {
      const data = await window.DashboardDataLoader.load(file);
      const next = new window.RaboScanner().scan(data);
      scannerReport = next;
      sourceName = file.name;
      if (snapshot) renderKpis();
      $('#scanner-error').hidden = true;
      toast(`Scanner: ${next.dependencyCount} dependencies from ${sourceName}.`);
    } catch (error) {
      $('#scanner-error').hidden = false;
      $('#scanner-error').innerHTML = `${E(error.message)}${scannerReport ? ' The previously loaded scanner data remains visible.' : ''} <button data-action="choose-json">Select JSON</button>`;
    } finally {
      busy = false;
    }
  }

  function toast(message) {
    clearTimeout(toastTimer);
    $('#toast').textContent = message;
    $('#toast').hidden = false;
    toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 3500);
  }

  function openDialog(title, html) {
    $('#dialog-title').textContent = title;
    $('#dialog-body').innerHTML = html;
    if (!$('#detail-dialog').open) $('#detail-dialog').showModal();
  }

  function detail(kind) {
    if (!snapshot) return toast('Load dashboard data first.');
    const sumTable = rows => table(snapshot.ui.tables.summary, rows.map(r => [E(r.label), String(r.value), `${C.total(rows) ? Math.round(r.value / C.total(rows) * 100) : 0}%`]));
    const content = {
      pipeline: () => openDialog('Pipeline Status', `<p class="muted">${E(snapshot.pipeline.note)}</p><div class="table-wrap">${sumTable(snapshot.pipeline.summary)}</div><div class="table-wrap">${table(['Day', ...snapshot.pipeline.daily.series.map(s => s.label)], snapshot.pipeline.daily.labels.map((label, i) => [E(label), ...snapshot.pipeline.daily.series.map(s => String(s.values[i]))]))}</div>`),
      incidents: () => openDialog('Incidents Overview', `<div class="table-wrap">${sumTable(snapshot.incidents.severity)}</div>`),
      environments: () => openDialog('Environment Health', `<div class="table-wrap">${environmentTable()}</div>`),
      vulnerabilities: () => openDialog('Vulnerabilities', `<div class="table-wrap">${sumTable(snapshot.vulnerabilities.severity)}</div><h3>Top findings</h3><div class="table-wrap">${topVulnerabilityTable()}</div>`),
      certificates: () => openDialog('Expiring Certificates', `<div class="table-wrap">${certificateTable()}</div>`)
    };
    content[kind]?.();
  }

  function scanner() {
    if (backendView) {
      return openDialog('Backend Scanner Summary', `<div class="scanner-status">${icon('scan')}<div><strong>${backendView.totals.violations} total findings</strong><small>${E(backendSourceName || 'Backend report')}</small></div></div><p class="scanner-note">Dependency Scanner: ${backendView.scanners.dependency.total} findings. Checkmarx: ${backendView.scanners.checkmarx.total} findings.</p><button class="copilot-button" data-action="choose-backend-json">Change Backend Report</button>`);
    }
    const title = scannerReport?.title || snapshot?.kpis[0].title || 'Dependency Scanner';
    if (!scannerReport) return openDialog(title, '<p>Select <strong>rabo-dependency-scanner.json</strong> to display dependencies, or load backend report JSON for pipeline findings.</p><button class="copilot-button" data-action="choose-backend-json">Load Backend Report</button><button class="copilot-button" data-action="choose-json">Load Scanner JSON</button>');
    openDialog(title, `<div class="scanner-status">${icon('scan')}<div><strong>${scannerReport.dependencyCount} reported dependencies</strong><small>${E(sourceName)}</small></div></div><p class="scanner-note">${E(scannerReport.description)}</p>${dependencyRows(scannerReport.dependencies, false)}<button class="copilot-button" data-action="choose-json">Change JSON</button>`);
  }

  function settings() {
    const backendValue = backendSourceName || 'No backend report selected';
    openDialog('Settings', `<p>Charts: the <code>dashboard-data</code> block in the HTML.<br>Backend report: ${E(backendValue)}.<br>Scanner file: ${E(sourceName || 'No scanner JSON selected')}.</p><p class="muted">Charts are available as soon as the page opens. Backend scanner sections update after selecting the backend JSON output from the daily scan.</p><button class="copilot-button" data-action="choose-backend-json">Load Backend Report</button>`);
  }

  function action(name) {
    if (name === 'choose-json') { $('#detail-dialog').close(); return chooseFile(); }
    if (name === 'choose-backend-json') { $('#detail-dialog').close(); return chooseBackendFile(); }
    if (name === 'settings') return settings();
    if (!snapshot) return toast('Load dashboard data first.');
    if (name === 'scanner') return scanner();
    if (name === 'integrations') return openDialog('Integrated Tools', snapshot.integrations.map((i, index) => `<div class="scanner-finding"><button class="integration" data-integration="${index}"><span class="integration-symbol" style="--logo-color:${E(i.color)}">${icon(i.icon)}</span>${E(i.name)} -></button><p class="muted">${E(i.description)}</p></div>`).join(''));
    if (name === 'alerts') return openDialog('Critical Issues & Alerts', `<p><strong class="danger">${backendView ? backendView.totals.violations : (snapshot.kpis.find(k => k.id === 'critical-issues')?.value || 0)} issues</strong> currently visible in the loaded data.</p><div class="table-wrap">${topVulnerabilityTable()}</div><h3>Expiring certificates</h3><div class="table-wrap">${certificateTable()}</div>`);
    if (name === 'copilot') return openDialog('AI Scrum Master', `<p class="muted">Local summary generated from the loaded data.</p><ul class="dialog-list"><li><strong>${C.total(snapshot.incidents.severity)} open incidents</strong> require attention.</li><li><strong>${backendView ? backendView.totals.violations : C.total(snapshot.vulnerabilities.severity)} findings</strong> are recorded.</li><li><strong>${snapshot.certificates.filter(c => c.expiresInDays <= snapshot.healthRules.certificateWarningDays).length} certificates</strong> expire within 30 days.</li><li><strong>${snapshot.environments.filter(e => e.status !== snapshot.healthRules.healthyStatus).map(e => E(e.name)).join(', ') || 'No environments'}</strong> flagged for review.</li></ul><p class="scanner-note">This packaged demo uses local-only data.</p>`);
  }

  function navigate(target) {
    if (!snapshot) return;
    activeNavigation = target;
    document.querySelectorAll('[data-nav]').forEach(button => {
      button.classList.toggle('active', button.dataset.nav === target);
      if (button.dataset.nav === target) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
    $('#sidebar').classList.remove('open');
    $('#menu-toggle').setAttribute('aria-expanded', 'false');
    const panel = document.getElementById(target);
    if (target === 'operations-wall' || target === 'overview') window.scrollTo({ top: 0, behavior: 'smooth' });
    else if (panel) {
      panel.scrollIntoView({ behavior: 'smooth', block: 'center' });
      panel.classList.remove('panel-highlight');
      void panel.offsetWidth;
      panel.classList.add('panel-highlight');
    } else if (target === 'settings') settings();
    else if (target === 'reports') openDialog('Snapshot Report', `<p class="muted">Loaded data snapshot - ${E(snapshot.meta.snapshotAt)}</p><button class="copilot-button" id="download-report">Download snapshot JSON</button>`);
    else if (snapshot.menuContent[target]) {
      const m = snapshot.menuContent[target];
      openDialog(m.title, `<p class="muted">${E(m.description)}</p>${m.items.length ? `<ul class="dialog-list">${m.items.map(item => `<li>${E(item)}</li>`).join('')}</ul>` : ''}`);
    }
  }

  document.addEventListener('click', event => {
    const nav = event.target.closest('[data-nav]');
    if (nav) return navigate(nav.dataset.nav);
    const details = event.target.closest('[data-detail]');
    if (details) return detail(details.dataset.detail);
    const act = event.target.closest('[data-action]');
    if (act) return action(act.dataset.action);
    const integration = event.target.closest('[data-integration]');
    if (integration && snapshot) {
      const i = snapshot.integrations[Number(integration.dataset.integration)];
      if (i.action === 'scanner') return scanner();
      return openDialog(i.name, `<p>${E(i.description)}</p><p class="muted">Data mode: ${E(snapshot.meta.dataMode)}</p>`);
    }
    if (event.target.closest('#download-report')) {
      const exported = backendView ? { generatedAt: backendView.generatedAt, totals: backendView.totals, pipelines: backendView.pipelines } : snapshot;
      const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = backendView ? 'backend-report-view.json' : 'operations-wall-snapshot.json';
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  });

  $('#scanner-file').addEventListener('change', event => loadScanner(event.target.files[0]));
  $('#backend-report-file').addEventListener('change', event => loadBackendReport(event.target.files[0]));
  $('#refresh').addEventListener('click', () => loadEmbedded(true));
  $('#close-dialog').addEventListener('click', () => $('#detail-dialog').close());
  $('#detail-dialog').addEventListener('click', event => {
    if (event.target === $('#detail-dialog')) {
      const rect = event.target.getBoundingClientRect();
      if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) event.target.close();
    }
  });
  $('#menu-toggle').addEventListener('click', () => {
    const open = $('#sidebar').classList.toggle('open');
    $('#menu-toggle').setAttribute('aria-expanded', String(open));
  });
  $('#fullscreen').addEventListener('click', async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else if (document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
      else toast('Fullscreen is not supported in this browser.');
    } catch {
      toast('Fullscreen is unavailable in this window.');
    }
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      $('#sidebar').classList.remove('open');
      $('#menu-toggle').setAttribute('aria-expanded', 'false');
    }
  });

  loadEmbedded();
  renderBackendSections();
})();
