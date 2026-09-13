/* Reads a user-selected JSON file locally. No server, fetch, script injection or eval. */
(function (root) {
  'use strict';
  const BOM = String.fromCharCode(0xFEFF);
  root.DashboardDataLoader = {
    async load(file) {
      if (!file) throw new Error('Select the daily-scan report JSON file.');
      let text;
      try { text = await file.text(); }
      catch { throw new Error('The file could not be read. Select it again.'); }
      if (text.startsWith(BOM)) text = text.slice(1);
      try { return JSON.parse(text); }
      catch { throw new Error('Invalid JSON. Check the commas, quotation marks and braces in the file.'); }
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
