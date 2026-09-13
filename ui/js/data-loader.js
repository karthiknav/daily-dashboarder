/* Reads a user-selected JSON file locally. No server, fetch, script injection or eval. */
(function (root) {
  'use strict';
  root.DashboardDataLoader = {
    async load(file) {
      if (!file) throw new Error('Select the rabo-dependency-scanner.json file.');
      let text;
      try { text = await file.text(); }
      catch { throw new Error('The file could not be read. Select it again.'); }
      try { return JSON.parse(text.replace(/^\uFEFF/, '')); }
      catch { throw new Error('Invalid JSON. Check the commas, quotation marks and braces in the file.'); }
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
