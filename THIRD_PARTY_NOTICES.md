# Third-party notices — development distribution

This project has no declared open-source license for its original application code. Do not infer redistribution rights from dependency licenses.

| Component | Purpose | Upstream license |
| --- | --- | --- |
| Electron | Desktop runtime | MIT; Chromium and other bundled components have additional notices |
| React / React DOM | Local user interface | MIT |
| Zod | Shared validation and JSON Schema | MIT |
| node-semver | Release version comparison | ISC |
| TypeScript | Type checking | Apache-2.0 |
| Vite / Vitest / esbuild / tsx | Development and build | MIT (see exact installed packages) |
| electron-builder | Development packaging | MIT; transitive tooling licenses apply |
| Playwright Core | UI and Electron tests | Apache-2.0 |
| Go / golang.org/x/sys | Native helper toolchain and OS interfaces | BSD-3-Clause; bundled license in licenses/golang-x-sys-BSD.txt |
| Microsoft go-winio v0.6.2 | Local Windows named-pipe transport | MIT; bundled license in licenses/go-winio-MIT.txt |
| Wintun | Windows TUN driver, unmodified DLL from the pinned Xray release | Upstream LICENSE-Wintun bundled alongside wintun.dll |
| wyx2685/v2board | Referenced API contract; server source not bundled | MIT according to the inspected repository LICENSE |
| Xray-core | Xray-core 26.10.31, unmodified upstream executable; included for the package target | MPL-2.0; full text in resources/licenses/Xray-core-MPL-2.0.txt and native/<target>/LICENSE |
| Loyalsoldier/clash-rules | Separately distributed mainland-direct domain/IP data, converted to the client's JSON schema | GPL-3.0; full text, original source data and conversion tool included under rules/ in the binary package |

The lockfile is the dependency inventory for this development revision. Electron binary distributions contain their own LICENSE and Chromium license notice. Those files must remain in packaged distributions. Before a production release, generate an inventory of the actual installed/bundled versions, review their licenses, add actual helper notices, and supply corresponding source/modification notices where required.

The unmodified Xray-core executable is obtained from https://github.com/XTLS/Xray-core/releases/tag/v26.10.31. Corresponding source is available at https://github.com/XTLS/Xray-core/tree/v26.10.31 (source archive: https://github.com/XTLS/Xray-core/archive/refs/tags/v26.10.31.tar.gz). No Xray source modifications were made. Exact upstream archive and executable SHA-256 values are recorded in resources/core-lock.json. The bundled executable must retain its LICENSE and this source-availability notice. Upstream geosite/geoip datasets are deliberately not bundled; the compiler currently uses explicit local rule data.

Rule-data source: https://github.com/Loyalsoldier/clash-rules/tree/611f7e9db13b5c824233ed7451abdf867fc08a41. On 2026-10-31 the original direct.txt and cncidr.txt payloads were converted into baseline.json, preserving exact domains separately from suffix domains. No advertising/blocking/application-specific lists were imported. The original data, GPL-3.0 license, exact SHA-256 manifest and standalone GPL-3.0-only conversion script are supplied with both source and binary distributions. This data and its conversion script form a separately licensed aggregate; the application's original code has no declared open-source license. To reproduce the binary package's dataset, run `python3 rules/import-rules.py rules` from its resources directory. Source checkout command: `npm run rules:import`. All rule data is provided without warranty under its included license.
