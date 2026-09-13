/* Renders the daily_scan.py report JSON (write_report() output) as a dashboard.
   Single data source: no embedded demo data, no separate scanner JSON. */
(function () {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const $$ = selector => Array.from(document.querySelectorAll(selector));
  const C = window.DashboardCharts;
  const E = C.escape;

  const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'unknown'];
  const SEVERITY_COLORS = { critical: '#f13e40', high: '#ff8610', medium: '#ffd025', low: '#31db78', unknown: '#5d6e82' };
  const SEVERITY_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown' };
  const FAILED_RESULTS = new Set(['failed', 'partiallysucceeded', 'canceled']);
  const CERT_WARNING_DAYS = 60;
  const CERT_CRITICAL_DAYS = 14;
  const CERT_CAUTION_DAYS = 30;

  const PAGES = ['overview', 'dependency_scanner', 'checkmarx', 'pipelines', 'certificates', 'announcements'];
  const NAV_ITEMS = [
    { page: 'overview', icon: 'overview', label: 'Overview' },
    { page: 'dependency_scanner', icon: 'bug', label: 'Dependency Scanner' },
    { page: 'checkmarx', icon: 'shield', label: 'Checkmarx' },
    { page: 'pipelines', icon: 'pipeline', label: 'Pipelines' },
    { page: 'certificates', icon: 'certificate', label: 'Certificates' },
    { page: 'announcements', icon: 'announcement', label: 'Announcements' }
  ];

  let view = null;
  let sourceName = '';
  let activePage = 'overview';
  const filters = {
    dependency_scanner: { severity: '', readyOnly: false },
    checkmarx: { severity: '', readyOnly: false }
  };
  let certificatesShowAll = false;
  const expandedRows = new Set();
  let busy = false;
  let toastTimer;

  function icon(name) { return window.Icons.svg(name); }

  function normalizeSeverity(value) {
    const text = String(value || '').trim().toLowerCase();
    if (text === 'critical') return 'critical';
    if (text === 'high' || text === 'error') return 'high';
    if (text === 'medium' || text === 'warning') return 'medium';
    if (text === 'low' || text === 'note' || text === 'info') return 'low';
    return 'unknown';
  }

  function categoryKey(value) {
    const text = String(value || '').trim().toLowerCase();
    if (text.includes('checkmarx')) return 'checkmarx';
    if (text.includes('depend')) return 'dependency_scanner';
    return text || 'other';
  }

  function severityClass(key) {
    return ({ critical: 'danger', high: 'warning', medium: 'medium', low: 'good', unknown: 'muted' }[key] || 'muted');
  }

  function severityBadge(key) {
    return `<span class="${severityClass(key)}">${E(SEVERITY_LABELS[key] || 'Unknown')}</span>`;
  }

  function emptySeverityCounts() { return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }; }

  function severityRows(counts) {
    return SEVERITY_KEYS.filter(key => counts[key]).map(key => ({ label: SEVERITY_LABELS[key], value: counts[key], color: SEVERITY_COLORS[key] }));
  }

  function summaryText(entry) {
    const payload = entry.finding || {};
    const packageName = payload.package || payload.name;
    if (packageName) return `${packageName} ${payload.currentVersion || ''}`.trim();
    if (payload.rule || payload.file) return `${payload.rule || 'Rule'} in ${payload.file || 'unknown file'}`;
    return 'Finding';
  }

  function prLabel(prUrl) {
    const match = /pullrequest\/(\d+)/i.exec(prUrl || '');
    return match ? `PR #${match[1]}` : 'View PR';
  }

  function remediationCell(remediation) {
    const r = remediation || {};
    if (r.prUrl) return `<a href="${E(r.prUrl)}" target="_blank" rel="noopener noreferrer">${E(prLabel(r.prUrl))} &rarr;</a>`;
    if (r.attempted === false) return '<span class="muted">Not attempted</span>';
    if (r.success === false) return `<span class="danger">${E(r.notes || 'Fix failed')}</span>`;
    return `<span class="muted">${E(r.notes || 'No automated fix')}</span>`;
  }

  function relativeTime(iso) {
    if (!iso) return '—';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '—';
    const diffMs = Date.now() - date.getTime();
    const minutes = Math.round(diffMs / 60000);
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.round(hours / 24);
    return `${days}d ago`;
  }

  // --- Build the view model from the raw report ---------------------------

  function normalizePipeline(entry, index) {
    if (entry.error) {
      return { target: entry.target, name: entry.target || `Pipeline ${index + 1}`, error: entry.error, findings: [] };
    }
    const findings = (entry.findings || []).map(f => ({
      category: categoryKey(f.category),
      severityKey: normalizeSeverity(f.severity),
      summary: f.summary || summaryText(f),
      finding: f.finding || {},
      remediation: f.remediation || {}
    }));
    return {
      target: entry.target,
      pipeline: entry.pipeline,
      project: entry.project || '',
      name: entry.pipeline || entry.target || `Pipeline ${index + 1}`,
      buildId: entry.buildId,
      buildNumber: entry.buildNumber,
      buildUrl: entry.buildUrl,
      buildResult: String(entry.buildResult || '').toLowerCase(),
      buildResultLabel: entry.buildResult || 'Unknown',
      buildFinishedAt: entry.buildFinishedAt,
      violationCounts: entry.violationCounts || {},
      findings
    };
  }

  function buildCategoryView(pipelines, key) {
    const rows = [];
    const totals = emptySeverityCounts();
    pipelines.forEach(pipeline => {
      if (pipeline.error) return;
      const findings = pipeline.findings.filter(f => f.category === key);
      if (!findings.length) return;
      const severityCounts = emptySeverityCounts();
      findings.forEach(f => { severityCounts[f.severityKey] += 1; totals[f.severityKey] += 1; });
      const readyCount = findings.filter(f => f.remediation.prUrl).length;
      const rank = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      rows.push({
        name: pipeline.name,
        target: pipeline.target,
        project: pipeline.project,
        buildUrl: pipeline.buildUrl,
        buildFinishedAt: pipeline.buildFinishedAt,
        severityCounts,
        total: findings.length,
        readyCount,
        findings: findings.slice().sort((a, b) => rank[a.severityKey] - rank[b.severityKey])
      });
    });
    rows.sort((a, b) => (b.severityCounts.critical - a.severityCounts.critical) || (b.severityCounts.high - a.severityCounts.high) || (b.total - a.total));
    return { rows, totals };
  }

  function pipelineSortRank(pipeline) {
    if (pipeline.error) return 0;
    if (pipeline.buildResult === 'failed') return 1;
    if (FAILED_RESULTS.has(pipeline.buildResult)) return 2;
    return 3;
  }

  function normalizeCertificate(cert) {
    return {
      name: cert.name || 'Unnamed certificate',
      environment: cert.environment || '—',
      expiresOn: cert.expiresOn || null,
      expiresInDays: Number.isFinite(cert.expiresInDays) ? cert.expiresInDays : null
    };
  }

  function normalizeAnnouncement(item) {
    return {
      id: item.id,
      subject: item.subject || 'Untitled announcement',
      from: item.from || '',
      receivedAt: item.receivedAt || null,
      priority: (item.priority || 'normal').toLowerCase(),
      summary: item.summary || '',
      link: item.link || null
    };
  }

  function numberOr(value, fallback) { return Number.isFinite(value) ? value : fallback; }

  function buildView(report) {
    const pipelines = (report.pipelines || []).map(normalizePipeline);
    const categories = {
      dependency_scanner: buildCategoryView(pipelines, 'dependency_scanner'),
      checkmarx: buildCategoryView(pipelines, 'checkmarx')
    };
    const certificates = (report.certificates || []).map(normalizeCertificate).sort((a, b) => numberOr(a.expiresInDays, Infinity) - numberOr(b.expiresInDays, Infinity));
    const announcements = (report.announcements || []).map(normalizeAnnouncement).sort((a, b) => new Date(b.receivedAt || 0) - new Date(a.receivedAt || 0));

    const reportSummary = report.summary || {};
    const failedComputed = pipelines.filter(p => !p.error && FAILED_RESULTS.has(p.buildResult)).length;
    const readyComputed = pipelines.reduce((sum, p) => sum + p.findings.filter(f => f.remediation.prUrl).length, 0);
    const severityComputed = emptySeverityCounts();
    pipelines.forEach(p => p.findings.forEach(f => { severityComputed[f.severityKey] += 1; }));

    const summary = {
      totalPipelines: numberOr(reportSummary.totalPipelines, pipelines.filter(p => !p.error).length),
      pipelinesFailed: numberOr(reportSummary.pipelinesFailed, failedComputed),
      totalViolations: numberOr(reportSummary.totalViolations, categories.dependency_scanner.rows.reduce((s, r) => s + r.total, 0) + categories.checkmarx.rows.reduce((s, r) => s + r.total, 0)),
      violationsByCategory: reportSummary.violationsByCategory || {
        dependency_scanner: categories.dependency_scanner.totals ? Object.values(categories.dependency_scanner.totals).reduce((a, b) => a + b, 0) : 0,
        checkmarx: categories.checkmarx.totals ? Object.values(categories.checkmarx.totals).reduce((a, b) => a + b, 0) : 0
      },
      violationsBySeverity: reportSummary.violationsBySeverity && Object.keys(reportSummary.violationsBySeverity).length ? reportSummary.violationsBySeverity : severityComputed,
      readyPrCount: numberOr(reportSummary.readyPrCount, readyComputed),
      certificatesExpiringSoon: numberOr(reportSummary.certificatesExpiringSoon, certificates.filter(c => numberOr(c.expiresInDays, Infinity) <= CERT_WARNING_DAYS).length),
      unreadAnnouncements: numberOr(reportSummary.unreadAnnouncements, announcements.length)
    };

    return { generatedAt: report.generatedAt, pipelines, categories, certificates, announcements, summary };
  }

  // --- Rendering ------------------------------------------------------------

  function table(headers, rows, className) {
    const klass = className || '';
    return `<table class="${klass}"><thead><tr>${headers.map(h => `<th scope="col">${E(h)}</th>`).join('')}</tr></thead><tbody>${rows.length ? rows.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${headers.length}" class="muted">No records available.</td></tr>`}</tbody></table>`;
  }

  function renderNav() {
    $('#side-nav').innerHTML = NAV_ITEMS.map(item => `<button class="nav-item ${item.page === activePage ? 'active' : ''}" data-page="${item.page}" ${item.page === activePage ? 'aria-current="page"' : ''}>${icon(item.icon)}<span>${E(item.label)}</span></button>`).join('');
  }

  function renderKpis() {
    const s = view.summary;
    const depCrit = view.categories.dependency_scanner.totals.critical || 0;
    const depHigh = view.categories.dependency_scanner.totals.high || 0;
    const cxCrit = view.categories.checkmarx.totals.critical || 0;
    const cxHigh = view.categories.checkmarx.totals.high || 0;
    const soonestCert = view.certificates.find(c => Number.isFinite(c.expiresInDays));
    const tiles = [
      { page: 'dependency_scanner', icon: 'bug', color: '#f24149', value: s.violationsByCategory.dependency_scanner || 0, label: 'Dependency Violations', detail: `${depCrit} crit &middot; ${depHigh} high` },
      { page: 'checkmarx', icon: 'shield', color: '#36aa50', value: s.violationsByCategory.checkmarx || 0, label: 'Checkmarx Violations', detail: `${cxCrit} crit &middot; ${cxHigh} high` },
      { page: 'pipelines', icon: 'pipeline', color: '#a258eb', value: `${s.pipelinesFailed} / ${s.totalPipelines}`, label: 'Pipelines Failed', detail: 'view builds' },
      { page: 'certificates', icon: 'certificate', color: '#ffc400', value: s.certificatesExpiringSoon, label: `Certs Expiring &le;${CERT_WARNING_DAYS}d`, detail: soonestCert ? `soonest: ${soonestCert.expiresInDays}d` : 'none' },
      { page: 'announcements', icon: 'announcement', color: '#4399ff', value: s.unreadAnnouncements, label: 'Announcements', detail: 'view all' }
    ];
    $('#kpis').innerHTML = tiles.map(t => `<button class="kpi-card kpi-card-link" style="--accent:${E(t.color)}" data-page="${t.page}"><h2 class="kpi-title">${t.label}</h2><div class="kpi-body"><span class="kpi-art">${icon(t.icon)}</span><div><div class="kpi-number">${t.value}</div><div class="kpi-label">${t.detail}</div></div></div></button>`).join('');
  }

  function rankingRows(rows) {
    if (!rows.length) return '<p class="muted">No findings.</p>';
    const maxTotal = Math.max(...rows.map(r => r.total));
    const barSegments = row => SEVERITY_KEYS.map(key => {
      const width = maxTotal ? (row.severityCounts[key] / maxTotal * 100) : 0;
      return width ? `<span style="width:${width}%;background:${SEVERITY_COLORS[key]}" title="${SEVERITY_LABELS[key]}: ${row.severityCounts[key]}"></span>` : '';
    }).join('');
    return `<div class="ranking-list">${rows.map(row => `
      <div class="ranking-row">
        <div class="ranking-name" title="${E(row.name)}${row.project ? ' · ' + E(row.project) : ''}">${E(row.name)}</div>
        <div class="ranking-bar">${barSegments(row)}</div>
        <div class="ranking-total" title="${SEVERITY_KEYS.filter(k => row.severityCounts[k]).map(k => `${row.severityCounts[k]} ${SEVERITY_LABELS[k].toLowerCase()}`).join(', ')}">${row.total}</div>
      </div>`).join('')}</div>`;
  }

  function categoryOverviewPanel(key, title) {
    const data = view.categories[key];
    const severity = severityRows(data.totals);
    const total = data.rows.reduce((sum, r) => sum + r.total, 0);
    const legendKeys = SEVERITY_KEYS.filter(k => data.totals[k]);
    return `<div class="panel overview-chart-panel">
        <div class="panel-heading"><h2>${E(title)}</h2><span class="panel-total">${total} finding${total === 1 ? '' : 's'}</span></div>
        <div class="overview-panel-body">
          ${severity.length ? `<div class="chart-and-legend">${C.donut(severity, 'Findings')}${C.legend(severity, true)}</div>` : '<p class="muted">No findings.</p>'}
          <div class="overview-ranking">
            <div class="overview-ranking-heading">
              <h3>By pipeline</h3>
              ${legendKeys.length ? `<ul class="ranking-legend">${legendKeys.map(k => `<li><span class="swatch" style="--swatch:${SEVERITY_COLORS[k]}"></span>${SEVERITY_LABELS[k]}</li>`).join('')}</ul>` : ''}
            </div>
            ${rankingRows(data.rows)}
          </div>
        </div>
      </div>`;
  }

  function renderOverviewCharts() {
    $('#overview-charts').innerHTML = categoryOverviewPanel('dependency_scanner', 'Dependency Scanner') + categoryOverviewPanel('checkmarx', 'Checkmarx');
  }

  function findingRow(finding) {
    const payload = finding.finding || {};
    const identifier = payload.cve || (payload.file ? `${payload.file}${payload.line ? ':' + payload.line : ''}` : '—');
    return `<tr class="finding-row"><td></td><td>${E(finding.summary)}</td><td colspan="4">${severityBadge(finding.severityKey)}</td><td>${E(identifier)}</td><td>${remediationCell(finding.remediation)}</td></tr>`;
  }

  function renderCategoryPage(key) {
    const root = $(`#${key}-content`);
    const data = view.categories[key];
    const state = filters[key];
    const rows = data.rows.filter(row => {
      if (state.readyOnly && row.readyCount === 0) return false;
      if (state.severity && !row.findings.some(f => f.severityKey === state.severity)) return false;
      return true;
    });

    if (!rows.length) {
      root.innerHTML = '<p class="muted">No pipelines match the current filters.</p>';
      return;
    }

    const headLabel = key === 'dependency_scanner' ? 'Package / CVE' : 'Rule / File:Line';
    const bodyRows = rows.map(row => {
      const rowKey = `${key}:${row.target}`;
      const expanded = expandedRows.has(rowKey);
      const visibleFindings = state.severity ? row.findings.filter(f => f.severityKey === state.severity) : row.findings;
      const detailRows = expanded ? visibleFindings.map(findingRow).join('') : '';
      return `<tr class="pipeline-row ${expanded ? 'expanded' : ''}" data-toggle-row="${E(rowKey)}">
          <td class="expand-cell">${expanded ? '&#9662;' : '&#9656;'}</td>
          <td>${E(row.name)}${row.project ? `<span class="row-subtext">${E(row.project)}</span>` : ''}</td>
          <td class="num critical">${row.severityCounts.critical || ''}</td>
          <td class="num warning">${row.severityCounts.high || ''}</td>
          <td class="num medium">${row.severityCounts.medium || ''}</td>
          <td class="num good">${row.severityCounts.low || ''}</td>
          <td class="num">${row.readyCount}/${row.total}</td>
          <td>${relativeTime(row.buildFinishedAt)}</td>
        </tr>${expanded ? `<tr class="finding-head-row" data-toggle-row="${E(rowKey)}"><td></td><td>${E(headLabel)}</td><td colspan="4">Severity</td><td>Details</td><td>Remediation</td></tr>${detailRows}` : ''}`;
    }).join('');

    root.innerHTML = `<div class="table-wrap"><table class="accordion-table">
        <thead><tr><th></th><th scope="col">Pipeline</th><th scope="col">Crit</th><th scope="col">High</th><th scope="col">Med</th><th scope="col">Low</th><th scope="col">PRs Ready</th><th scope="col">Last scanned</th></tr></thead>
        <tbody>${bodyRows}</tbody>
      </table></div>`;
  }

  function renderPipelinesPage() {
    const rows = view.pipelines.slice().sort((a, b) => pipelineSortRank(a) - pipelineSortRank(b) || a.name.localeCompare(b.name));
    $('#pipelines-content').innerHTML = table(
      ['Pipeline', 'Project', 'Build #', 'Result', 'Finished', ''],
      rows.map(p => {
        if (p.error) {
          return [E(p.name), '—', '—', '<span class="danger">SCAN ERROR</span>', '—', `<span class="muted">${E(p.error)}</span>`];
        }
        const resultClass = p.buildResult === 'failed' ? 'danger' : FAILED_RESULTS.has(p.buildResult) ? 'warning' : p.buildResult === 'succeeded' ? 'good' : 'muted';
        const build = p.buildUrl ? `<a href="${E(p.buildUrl)}" target="_blank" rel="noopener noreferrer">${E(p.buildNumber || 'Build')}</a>` : E(p.buildNumber || '—');
        return [
          E(p.name), E(p.project || '—'), build,
          `<span class="${resultClass}">${E((p.buildResultLabel || 'UNKNOWN').toUpperCase())}</span>`,
          relativeTime(p.buildFinishedAt), ''
        ];
      })
    );
  }

  function renderCertificatesPage() {
    const visible = certificatesShowAll ? view.certificates : view.certificates.filter(c => numberOr(c.expiresInDays, Infinity) <= CERT_WARNING_DAYS);
    $('#certificates-content').innerHTML = table(
      ['Certificate', 'Environment', 'Expires On', 'Days Left'],
      visible.map(c => {
        const days = c.expiresInDays;
        const klass = days === null ? 'muted' : days <= CERT_CRITICAL_DAYS ? 'danger' : days <= CERT_CAUTION_DAYS ? 'warning' : 'good';
        const label = days === null ? 'Unknown' : days < 0 ? `${Math.abs(days)} days overdue` : `${days} days`;
        return [E(c.name), E(c.environment), E(c.expiresOn || '—'), `<span class="${klass}">${label}</span>`];
      })
    );
  }

  function renderAnnouncementsPage() {
    const root = $('#announcements-content');
    if (!view.announcements.length) {
      root.innerHTML = '<p class="muted">No announcements in this report.</p>';
      return;
    }
    root.innerHTML = `<ul class="announcement-list">${view.announcements.map(a => `
      <li class="announcement-item">
        <span class="priority-dot ${a.priority === 'high' ? 'danger' : 'muted'}">&#9679;</span>
        <div class="announcement-body">
          <div class="announcement-subject">${E(a.subject)}${a.from ? ` <span class="row-subtext">&mdash; ${E(a.from)}</span>` : ''}</div>
          ${a.summary ? `<p class="announcement-summary">${E(a.summary)}</p>` : ''}
          <span class="row-subtext">${relativeTime(a.receivedAt)}</span>
        </div>
        ${a.link ? `<a href="${E(a.link)}" target="_blank" rel="noopener noreferrer" class="text-link">open &rarr;</a>` : ''}
      </li>`).join('')}</ul>`;
  }

  function renderPage() {
    if (activePage === 'overview') { renderKpis(); renderOverviewCharts(); }
    else if (activePage === 'dependency_scanner' || activePage === 'checkmarx') renderCategoryPage(activePage);
    else if (activePage === 'pipelines') renderPipelinesPage();
    else if (activePage === 'certificates') renderCertificatesPage();
    else if (activePage === 'announcements') renderAnnouncementsPage();
  }

  function showPage(page) {
    activePage = PAGES.includes(page) ? page : 'overview';
    PAGES.forEach(p => { const section = $(`#page-${p}`); if (section) section.hidden = p !== activePage; });
    renderNav();
    if (view) renderPage();
  }

  function render() {
    $('#empty-state').hidden = true;
    $('#dashboard').hidden = false;
    document.body.classList.add('data-loaded');
    $('#source-label').textContent = sourceName ? `Report: ${sourceName}` : '';
    $('#footer-note').textContent = `Data source: ${sourceName || 'unknown'} &middot; generated ${view.generatedAt || 'unknown time'}`.replace('&middot;', '·');
    if (view.generatedAt) {
      const date = new Date(view.generatedAt);
      if (!Number.isNaN(date.getTime())) {
        $('#snapshot-time').hidden = false;
        $('#snapshot-time').dateTime = view.generatedAt;
        $('#snapshot-time').textContent = date.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC';
      }
    }
    showPage(activePage);
  }

  function toast(message) {
    clearTimeout(toastTimer);
    $('#toast').textContent = message;
    $('#toast').hidden = false;
    toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 3500);
  }

  function validateReport(data) {
    const require = (ok, message) => { if (!ok) throw new Error(`Invalid report: ${message}`); };
    require(data && typeof data === 'object', 'root must be a JSON object.');
    require(Array.isArray(data.pipelines), 'pipelines must be an array.');
    data.pipelines.forEach((entry, index) => {
      require(entry && typeof entry === 'object', `pipelines[${index}] must be an object.`);
      if (!entry.error) require(Array.isArray(entry.findings), `pipelines[${index}].findings must be an array when no error is present.`);
    });
    if (data.certificates !== undefined) require(Array.isArray(data.certificates), 'certificates must be an array.');
    if (data.announcements !== undefined) require(Array.isArray(data.announcements), 'announcements must be an array.');
    return data;
  }

  async function loadReport(file) {
    if (busy || !file) return;
    busy = true;
    try {
      const data = await window.DashboardDataLoader.load(file);
      view = buildView(validateReport(data));
      sourceName = file.name;
      render();
      $('#error-banner').hidden = true;
      toast(`Loaded ${sourceName}: ${view.summary.totalViolations} violations across ${view.summary.totalPipelines} pipelines.`);
    } catch (error) {
      $('#error-banner').hidden = false;
      $('#error-banner').textContent = `${error.message}${view ? ' The previously loaded report remains visible.' : ''}`;
    } finally {
      busy = false;
    }
  }

  function chooseFile() {
    if (busy) return;
    $('#report-file').value = '';
    $('#report-file').click();
  }

  document.querySelectorAll('[data-icon]').forEach(element => { element.innerHTML = icon(element.dataset.icon); });

  document.addEventListener('click', event => {
    const nav = event.target.closest('[data-page]');
    if (nav) { showPage(nav.dataset.page); return; }
    const action = event.target.closest('[data-action]');
    if (action && action.dataset.action === 'load-report') { chooseFile(); return; }
    const toggle = event.target.closest('[data-toggle-row]');
    if (toggle) {
      const key = toggle.dataset.toggleRow;
      if (expandedRows.has(key)) expandedRows.delete(key); else expandedRows.add(key);
      renderPage();
    }
  });

  document.addEventListener('change', event => {
    if (event.target.id === 'report-file') return loadReport(event.target.files[0]);
    if (event.target.classList.contains('severity-filter')) {
      const key = event.target.closest('[data-category]').dataset.category;
      filters[key].severity = event.target.value;
      renderPage();
    }
    if (event.target.classList.contains('ready-pr-filter')) {
      const key = event.target.closest('[data-category]').dataset.category;
      filters[key].readyOnly = event.target.checked;
      renderPage();
    }
    if (event.target.id === 'certificates-show-all') {
      certificatesShowAll = event.target.checked;
      renderPage();
    }
  });

  $('#load-report').addEventListener('click', chooseFile);
  $('#fullscreen').addEventListener('click', async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else if (document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
      else toast('Fullscreen is not supported in this browser.');
    } catch {
      toast('Fullscreen is unavailable in this window.');
    }
  });
  $('#menu-toggle').addEventListener('click', () => {
    const open = $('#sidebar').classList.toggle('open');
    $('#menu-toggle').setAttribute('aria-expanded', String(open));
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      $('#sidebar').classList.remove('open');
      $('#menu-toggle').setAttribute('aria-expanded', 'false');
    }
  });

  renderNav();
})();
