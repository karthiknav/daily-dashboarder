/* Local interface icons: no CDN, font service, or runtime download. */
(function (root) {
  'use strict';
  const paths = {
    wall:'<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 7h4v4H7zM14 7h3M14 11h3M7 15h3M7 18h3M14 15h3v3h-3z"/>',
    overview:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="10" r="3"/><path d="M6 19v-3a6 6 0 0 1 12 0v3M12 16v5"/>',
    pipeline:'<rect x="2" y="3" width="6" height="6" rx="1"/><rect x="16" y="3" width="6" height="6" rx="1"/><rect x="2" y="15" width="6" height="6" rx="1"/><rect x="16" y="15" width="6" height="6" rx="1"/><path d="M8 6h8M8 18h8M5 9v6M19 9v6M12 6v12"/>',
    warning:'<path d="m10.3 3.5-9 16A1.7 1.7 0 0 0 2.8 22h18.4a1.7 1.7 0 0 0 1.5-2.5l-9-16a2 2 0 0 0-3.4 0Z"/><path d="M12 8v7M12 18v.5"/>',
    shield:'<path d="M12 2c3 3 7 3 9 4v7c0 5-5 8-9 10-4-2-9-5-9-10V6c2-1 6-1 9-4Z"/><circle cx="12" cy="11" r="4"/><path d="M12 9v3M12 14v.1"/>',
    health:'<path d="M12 2c3 3 7 3 9 4v7c0 5-5 8-9 10-4-2-9-5-9-10V6c2-1 6-1 9-4Z"/><path d="M5 13h4l2-5 3 10 2-5h3"/>',
    bug:'<path d="M12 2c3 3 7 3 9 4v7c0 5-5 8-9 10-4-2-9-5-9-10V6c2-1 6-1 9-4Z"/><ellipse cx="12" cy="13" rx="4" ry="5"/><path d="M12 8v10M8 10 6 8M16 10l2-2M8 14H5M16 14h3M9 17l-2 2M15 17l2 2M10 8l-1-2M14 8l1-2"/>',
    checkshield:'<path d="m12 2 9 4v7c0 5-5 8-9 10-4-2-9-5-9-10V6z"/><path d="m7 12 3 3 6-7"/>',
    clipboard:'<rect x="5" y="4" width="14" height="18" rx="2"/><rect x="9" y="2" width="6" height="4" rx="1"/><path d="M8 10h2M13 10h3M8 14h2M13 14h3M8 18h2M13 18h3"/>',
    certificate:'<rect x="2" y="3" width="20" height="16" rx="2"/><path d="M6 7h12M6 11h7M6 15h6"/><circle cx="17" cy="16" r="3"/><path d="m15 19-1 4 3-2 3 2-1-4"/>',
    calendar:'<rect x="3" y="5" width="18" height="17" rx="2"/><path d="M7 2v6M17 2v6M3 10h18M7 14h3M14 14h3M7 18h3"/>',
    announcement:'<path d="m3 9 14-5v16L3 15zM3 9v6M7 16l2 6h4l-2-7M20 8l3-2M20 12h3M20 16l3 2"/>',
    report:'<path d="M5 2h10l5 5v15H5zM15 2v6h5M9 12v6M13 10v8M17 14v4"/>',
    settings:'<path d="m9 2-1 3-3 1-3 4 2 2-1 4 4 3 3-1 2 4 4-1 1-3 4-2 1-4-3-2V7l-4-3-3 1z"/><circle cx="12" cy="12" r="3"/>',
    bot:'<rect x="3" y="7" width="18" height="13" rx="4"/><path d="M12 7V3M1 11v5M23 11v5M8 23h8M8 16h8"/><circle cx="12" cy="2" r="1"/><circle cx="8" cy="12" r="1"/><circle cx="16" cy="12" r="1"/>',
    sparkles:'<path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5zM20 2v4M18 4h4"/>',
    monitor:'<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4M6 13h3l2-5 3 4h4"/>',
    refresh:'<path d="M21 3v6h-6M3 21v-6h6M20 9A8 8 0 0 0 6 5L3 8M4 15a8 8 0 0 0 14 4l3-3"/>',
    scan:'<path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5M2 12h20"/><path d="M7 7h3v3H7zM14 7h3v3h-3zM7 15h3v3H7zM14 15h3v3h-3z"/>',
    bell:'<path d="M18 8a6 6 0 0 0-12 0c0 8-3 8-3 10h18c0-2-3-2-3-10M10 22h4"/>',
    close:'<path d="m6 6 12 12M6 18 18 6"/>',
    menu:'<path d="M3 6h18M3 12h18M3 18h18"/>',
    code:'<path d="m8 7-5 5 5 5M16 7l5 5-5 5M14 3l-4 18"/>',
    cloud:'<path d="M6 19a5 5 0 1 1 1-10 7 7 0 0 1 13 2 4 4 0 0 1-1 8z"/>',
    check:'<rect x="3" y="3" width="18" height="18" rx="5"/><path d="m7 12 4 4 6-8"/>',
    sonar:'<path d="M3 20A17 17 0 0 1 20 3M8 21A13 13 0 0 1 21 8M14 21a7 7 0 0 1 7-7"/>',
    teams:'<circle cx="9" cy="5" r="3"/><circle cx="18" cy="7" r="2"/><path d="M3 10h12v10H3zM15 11h7v8h-7M6 13h6M9 13v5"/>',
    cube:'<path d="m12 2 10 5v10l-10 5-10-5V7zM2 7l10 5 10-5M12 12v10"/>'
  };
  root.Icons = { svg(name, className = '') { return `<svg class="icon ${className}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.code}</svg>`; }};
})(window);
