# Operations Wall — embedded chart data and a separate scanner JSON

## Open the dashboard

1. Extract the entire ZIP archive.
2. Double-click **index.html**.
3. Charts, indicators, tables and menus appear automatically.
4. On the first card, click **Load Scanner JSON** and select **rabo-dependency-scanner.json**.

No server, Python, Node.js, internet connection or library installation is required.

An external JSON file cannot be read automatically and portably by a page opened through `file://`. The scanner therefore requires file selection. Charts load automatically from the HTML. Scanner data is not duplicated or hidden in the HTML or JavaScript.

## Chart data

Chart data is included near the end of **index.html** in this block:

```html
<script type="application/json" id="dashboard-data">
  { ... }
</script>
```

The block contains pure JSON, not executable JavaScript. `js/app.js` reads it with `JSON.parse()` when the page opens. Dashboard records are not stored in `.js` files.

To change charts or menus, edit the JSON object in the HTML, save the file and reload the browser page. The dashboard refresh button rebuilds charts from the JSON block in the currently open page.

## Scanner data

Scanner records are stored exclusively in **rabo-dependency-scanner.json**, independently of the chart data.

The supplied file contains:

| Name | Maven coordinates | Version |
| --- | --- | --- |
| netty-codec-classes-quic | io.netty:netty-codec-classes-quic | 4.2.17.Final |
| netty-codec-http3 | io.netty:netty-codec-http3 | 4.2.17.Final |
| annotations | org.jetbrains:annotations | 26.0.2 |

Example entry:

```json
{
  "name": "netty-codec-classes-quic",
  "groupId": "io.netty",
  "artifactId": "netty-codec-classes-quic",
  "versions": ["4.2.17.Final"],
  "advisories": []
}
```

Add entries to `dependencies` and additional versions to `versions`. Leave `advisories` empty when advisory identifiers and severity assessments have not been supplied. If those details are available in your source report, each advisory may contain `id` and `severity`.

The included components and versions were supplied by the user. No severity assessments, CVE identifiers or conclusions about affected versions have been invented. This component displays the selected report; it does not perform live scans and is not an official Rabobank SDK.

The **RaboBank Dependency Scanner** card is first, at the top left of the main area. After loading the file, it displays the dependency count, names, Maven coordinates and versions. Click the summary to open the details. Long dependency lists are scrollable.

After editing the JSON file on disk, click **Change JSON** on the card and select it again. Reopening or reloading the page requires selecting the scanner JSON again. If loading or validation fails, the charts remain functional and the last valid scanner report stays visible.

## Files

```text
operations-wall/
  index.html                    — dashboard and embedded chart JSON
  rabo-dependency-scanner.json   — scanner records only
  README.md
  css/styles.css
  js/app.js
  js/data-loader.js
  js/charts.js
  js/icons.js
  vendor/rabo-scanner/rabo-scanner.js
  vendor/rabo-scanner/rabo-scanner.css
  assets/favicon.svg
```

The six main panels and six indicator cards remain available alongside the scanner card. Chart and scanner data are independent: changing the scanner report does not automatically change the other panels.

All interface labels, buttons, loading messages, errors and documentation are in English. Names and versions in a user-selected scanner report are displayed as supplied.
