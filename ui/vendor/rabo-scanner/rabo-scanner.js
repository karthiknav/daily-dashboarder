/** Local dependency-report adapter. This does not perform live vulnerability scans. */
(function (root) {
  'use strict';
  class RaboScanner {
    static version = '2.0.0';
    scan(data) {
      const require = (valid, message) => { if (!valid) throw new Error(`Scanner JSON: ${message}`); };
      require(data && data.schemaVersion === 1, 'schemaVersion must be 1.');
      require(typeof data.title === 'string' && data.title.trim(), 'title is required.');
      require(typeof data.description === 'string', 'description must be text.');
      require(Array.isArray(data.dependencies), 'dependencies must be an array.');
      const dependencies = data.dependencies.map(dependency => {
        ['name','groupId','artifactId'].forEach(key => require(typeof dependency?.[key] === 'string' && dependency[key].trim(), `each dependency needs ${key}.`));
        require(Array.isArray(dependency.versions) && dependency.versions.length > 0 && dependency.versions.every(v => typeof v === 'string' && v.trim()), 'versions must contain one or more version strings.');
        require(Array.isArray(dependency.advisories), 'advisories must be an array (empty if no advisories were supplied).');
        dependency.advisories.forEach(advisory => require(typeof advisory?.id === 'string' && typeof advisory?.severity === 'string', 'advisories require id and severity.'));
        return {
          name: dependency.name,
          coordinates: `${dependency.groupId}:${dependency.artifactId}`,
          versions: [...dependency.versions],
          advisories: dependency.advisories.map(a => ({id:a.id,severity:a.severity}))
        };
      });
      return {
        title:data.title, description:data.description,
        dependencies, dependencyCount:dependencies.length,
        advisoryCount:dependencies.reduce((count,d) => count + d.advisories.length,0)
      };
    }
  }
  root.RaboScanner = RaboScanner;
})(typeof window !== 'undefined' ? window : globalThis);
