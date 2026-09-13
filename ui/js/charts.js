/* Small SVG chart renderer. Geometry and labels are derived only from supplied data. */
(function (root) {
  'use strict';
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const total = rows => rows.reduce((sum, row) => sum + row.value, 0);
  function donut(rows, label) {
    const sum = total(rows), radius = 55, circumference = 2 * Math.PI * radius;
    let offset = 0;
    const arcs = rows.map(row => {
      const length = sum ? row.value / sum * circumference : 0;
      const arc = `<circle cx="72" cy="72" r="${radius}" fill="none" stroke="${escape(row.color)}" stroke-width="15" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" transform="rotate(-90 72 72)"><title>${escape(row.label)}: ${row.value}</title></circle>`;
      offset += length;
      return arc;
    }).join('');
    return `<div class="donut"><svg viewBox="0 0 144 144" role="img" aria-label="${escape(label)}: ${sum}. ${escape(rows.map(r => `${r.label}: ${r.value}`).join(', '))}"><circle cx="72" cy="72" r="55" fill="none" stroke="#25384b" stroke-width="15"/>${arcs}<text x="72" y="75" text-anchor="middle" class="donut-number">${sum}</text><text x="72" y="94" text-anchor="middle" class="donut-label">${escape(label)}</text></svg></div>`;
  }
  function legend(rows, compact = false) {
    const sum = total(rows);
    return `<ul class="legend">${rows.map(r => `<li><span class="swatch" style="--swatch:${escape(r.color)}"></span><span>${escape(r.label)}</span><span class="legend-value">${r.value}${compact ? '' : ' '} (${sum ? Math.round(r.value / sum * 100) : 0}%)</span></li>`).join('')}</ul>`;
  }
  function bars(labels, series, options = {}) {
    const width = 340, height = 193, top = 13, bottom = 155, left = 30, right = 331;
    const count = labels.length;
    if (!count) return '<p class="muted">No data available.</p>';
    const totals = labels.map((_, i) => series.reduce((sum, s) => sum + s.values[i], 0));
    const maxValue = Math.max(1, ...totals);
    const maximum = options.maximum || Math.ceil(maxValue / 5) * 5;
    const step = (right - left) / count, barWidth = Math.min(26, step * .56), plotHeight = bottom - top;
    let elements = '';
    for (let i = 0; i <= 4; i++) {
      const y = bottom - plotHeight * i / 4;
      elements += `<line class="grid-line" x1="${left}" x2="${right}" y1="${y}" y2="${y}"/><text x="${left - 10}" y="${y + 4}" text-anchor="end" class="chart-text">${Math.round(maximum * i / 4)}</text>`;
    }
    labels.forEach((label, i) => {
      const x = left + i * step + (step - barWidth) / 2;
      let y = bottom;
      series.forEach(s => {
        const value = s.values[i], barHeight = value / maximum * plotHeight;
        y -= barHeight;
        const color = s.colors ? s.colors[i] : s.color;
        elements += `<rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx=".8" fill="${escape(color)}" stroke="${escape(color)}" stroke-width=".4"><title>${escape(label)} — ${escape(s.label)}: ${value}</title></rect>`;
      });
      if (options.valueLabels) elements += `<text x="${x + barWidth / 2}" y="${y - 7}" text-anchor="middle" class="chart-text">${totals[i]}</text>`;
      elements += `<text x="${x + barWidth / 2}" y="179" text-anchor="middle" class="chart-text">${escape(label)}</text>`;
    });
    return `<div class="bar-chart"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${escape(options.label || 'Bar chart')}"><title>${escape(labels.map((label,i)=> `${label}: ${series.map(s=>`${s.label} ${s.values[i]}`).join(', ')}`).join('; '))}</title>${elements}</svg></div>`;
  }
  function sparkline(values, color) {
    if (!values.length) return '';
    const min = Math.min(...values) - .5, max = Math.max(...values) + .5;
    const points = values.map((v, i) => `${2 + i / Math.max(1,values.length - 1) * 70},${19 - (v - min) / (max - min) * 16}`).join(' ');
    return `<svg viewBox="0 0 74 22" class="sparkline" role="img" aria-label="Seven-day health trend: ${escape(values.join(', '))}"><polyline points="${points}" fill="none" stroke="${escape(color)}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  }
  root.DashboardCharts = {donut, legend, bars, sparkline, escape, total};
})(typeof window !== 'undefined' ? window : globalThis);
