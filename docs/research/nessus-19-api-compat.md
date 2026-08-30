# Nessus 19.x REST API Compatibility Research (CredFlow)

**Date:** 2026-08-30
**Scope:** Whether Tenable Nessus 19.x (specifically 19.18.4, build 20038, Nessus Professional) changed its REST API in ways that break CredFlow's API usage.
**Method:** Official Tenable documentation (developer.tenable.com, docs.tenable.com) + empirical verification against the live server at `https://192.168.1.116:8834` (Nessus Professional 19.18.4 build 20038).

---

## Summary

CredFlow's REST API usage remains **largely compatible** with Nessus 19.18.4. All core lifecycle endpoints (session auth, template listing, scan create/launch/poll/export/delete, trash, folders) work as before. However, **two significant behavioral changes** were confirmed empirically and are not covered by official documentation:

1. **Template UUIDs are now 52-character strings** (e.g. `731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65`) instead of 36-char UUIDs. CredFlow treats these as opaque strings, so this is **not breaking** — but any code that validates UUID format would break.
2. **The `plugins.families` structure is no longer returned** by `GET /editor/scan/templates/{uuid}` or `GET /editor/scan/{id}`, and a `plugins` payload passed to `POST /scans` is **accepted but does not take effect** — **unless the request carries the `X-API-Version: 2` header**. With that header (which the web UI sends), `plugins.families` is fully returned and `plugins` payloads in `POST /scans` and `POST /policies` take effect. **RESOLVED:** CredFlow now sends `X-API-Version: 2` on every request (commit 26470cd), restoring plugin-family disabling on 19.x. Verified end-to-end: scan created via CredFlow with `--disabled-families "Denial of Service"` shows `status: "disabled"` in the scan's editor config.

A third notable change (documented by Tenable in 10.12.0 release notes): **unauthenticated file downloads now require a session token** — confirmed empirically (download without auth → HTTP 401).

**Version renumbering note:** The live server reports `server_version: 19.18.4` (engine) while `nessus_ui_version: 10.12.4` (UI). Official Tenable release notes and the lifecycle matrix still use the **10.x** scheme (latest 10.12.4, 2026-08-19). The claim that "10.x became 19.x" is **not confirmed by any official Tenable document**; the 19.x number appears to be the engine versioning scheme, distinct from the UI/10.x scheme. This is documented as an observed discrepancy.

---

## Version Info

| Field | Value | Source |
|---|---|---|
| `server_version` | `19.18.4` | Empirical: `GET /server/properties` on live server |
| `server_build` | `20038` | Empirical: `GET /server/properties` |
| `nessus_ui_version` | `10.12.4` | Empirical: `GET /server/properties` |
| `nessus_ui_build` | `38` | Empirical: `GET /server/properties` |
| `nessus_type` | `Nessus Professional` | Empirical: `GET /server/properties` |
| `template_version` | `202607231556` | Empirical: `GET /server/properties` |
| Latest official release | 10.12.4 (2026-08-19) | [Tenable Nessus 2026 Release Notes](https://docs.tenable.com/release-notes/Content/nessus/2026.htm) |
| Lifecycle matrix | 10.12.x GA April 2026, EoSS 10/31/2027, EOL 4/30/2028 | [Tenable Software Release Lifecycle Matrix](https://docs.tenable.com/pdfs/product-lifecycle-management/tenable-software-release-lifecycle-matrix.pdf) |

**Base URL scheme:** The local Nessus REST API is served at the server root with **no version prefix** — e.g. `https://host:8834/session`, `https://host:8834/scans`, `https://host:8834/editor/scan/templates`. This is unchanged. (The cloud Tenable Vulnerability Management API uses `https://cloud.tenable.com` with a different auth scheme — `X-ApiKeys` — and is a separate API surface; see [developer.tenable.com](https://developer.tenable.com/docs/welcome).)

---

## Endpoint-by-Endpoint Compatibility

| Endpoint | CredFlow usage | 19.x behavior (verified) | Verdict |
|---|---|---|---|
| `POST /session` | Login, returns `token` | Returns `{"token": "..."}`; set `X-Cookie: token=...` works | ✅ Compatible (empirical) |
| `GET /nessus6.js` | Regex `value:function(){return"UUID"}` → X-API-Token | Accessible without auth (HTTP 200). Contains **4** `value:function(){return"..."}` matches: `"top"`, `"nessuscli"`, `"winter"`, and the real 36-char UUID. CredFlow's primary regex is UUID-specific so it still matches the correct token. | ✅ Compatible (empirical) |
| `GET /server/status` | Health check | Returns `{"status":"ready", ...}` | ✅ Compatible (empirical) |
| `GET /server/properties` | Version/scanner info | Returns `server_version`, `server_build`, `nessus_ui_version`, etc. | ✅ Compatible (empirical) |
| `GET /editor/scan/templates` | List templates by name → uuid | Returns 21 templates; each has a **52-char** `uuid` | ✅ Compatible (empirical) |
| `GET /editor/scan/templates/{uuid}` | Template detail with `plugins.families` | Without `X-API-Version: 2` → `plugins` absent. **With `X-API-Version: 2` → full `plugins.families` (64 families, incl. `readOnly` flag)** | ✅ Compatible with v2 header (empirical) |
| `GET /editor/scan/{id}` | Source scan config clone | Without `X-API-Version: 2` → `plugins` absent. **With `X-API-Version: 2` → full `plugins.families`** | ✅ Compatible with v2 header (empirical) |
| `POST /scans` | Create with `uuid` + `settings` + `credentials` + `plugins` | Works with 52-char uuid. **Without X-API-Token → HTTP 412 "API is not available"**. `plugins` payload takes effect **only with `X-API-Version: 2`** (verified: DoS family `status: disabled` in editor config) | ✅ Compatible with v2 header (empirical) |
| `POST /scans/{id}/launch` | Launch scan | Returns `{"scan_uuid": "..."}` | ✅ Compatible (empirical) |
| `GET /scans/{id}` | Poll status | `info.status` returns `running`/`completed`/etc. | ✅ Compatible (empirical) |
| `POST /scans/{id}/export` | Export `nessus`/`db` | Works. `{"format":"nessus"}` and `{"format":"db","password":"..."}` both return `{"file": <id>, "token": "..."}`. Rejects running scans with "Can not export running scans". | ✅ Compatible (empirical) |
| `GET /scans/{id}/export/{file}/status` | Poll export readiness | Returns `{"status":"ready"}` | ✅ Compatible (empirical) |
| `GET /scans/{id}/export/{file}/download` | Download report | **Without auth → HTTP 401**; with `X-Cookie`+`X-API-Token` → HTTP 200. | ⚠️ **Changed** (empirical; matches 10.12.0 release note) |
| `DELETE /scans/{id}` | Permanent delete | HTTP 200 when scan not active; HTTP 409 "Can not delete an active scan" when running | ✅ Compatible (empirical) |
| `PUT /scans/{id}/folder` | Move to Trash | HTTP 200 with `{"folder_id":2}` | ✅ Compatible (empirical) |
| `GET /folders` | Trash folder id | Returns `Trash` (id 2) and `My Scans` (id 3) | ✅ Compatible (empirical) |
| `GET /scans` | List scans | Returns `scans` array (list). When empty, `scans` may be `null` — CredFlow handles with `or []`. | ✅ Compatible (empirical + known finding) |
| `GET /editor/template/list` (plural) | *(not used by CredFlow)* | **Errors**: `{"error":"Invalid 'id' field: invalid type 'string', expecting 'int'"}` | ⚠️ **Changed** (empirical; not used by CredFlow) |

---

## Breaking Changes Found

### 1. Template UUID format: 36-char → 52-char
- **Empirical:** All 21 templates on the live server return 52-char `uuid` values, e.g. `731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65` (len=52).
- **Documentation:** The official [List templates](https://developer.tenable.com/reference/editor-list-templates) reference shows 52-char UUIDs in its response examples (e.g. `aa17696a-f0ad-458a-a103-973c8f63752a7bd788d6be818b65`), confirming the new format is official.
- **Impact on CredFlow:** **None** — CredFlow treats UUIDs as opaque strings (`get_template_uuid`, `create_scan`). No UUID-format validation exists. ✅

### 2. `plugins.families` gated behind `X-API-Version: 2` — RESOLVED
- **Root cause (empirical):** Requests **without** the `X-API-Version: 2` header get `plugins: None` from `GET /editor/scan/templates/{uuid}` and `GET /editor/scan/{id}`, and `plugins` payloads in `POST /scans` / `POST /policies` are silently ignored. The web UI always sends this header; direct API clients that omit it see the regression.
- **With the header:** editor endpoints return full `plugins.families` (64 families, incl. `readOnly` flag), and `plugins` payloads take effect — verified: `POST /scans` with `{"Denial of Service": {"id": 9, "status": "disabled"}}` produces a scan whose editor config shows `status: "disabled"`.
- **Impact on CredFlow:** **Resolved by commit 26470cd** — `NessusClient._authenticate()` now sets `X-API-Version: 2` on the session, restoring `--disabled-families` and source-scan plugin inheritance on 19.x. Verified end-to-end on the live server.

### 3. Unauthenticated file downloads now require a session token
- **Documentation:** Tenable Nessus 10.12.0 release notes: *"If you previously used unauthenticated requests to download files from Tenable Nessus, you must now authenticate those requests with a session token."* ([2026 Release Notes](https://docs.tenable.com/release-notes/Content/nessus/2026.htm#10.12.0))
- **Empirical:** `GET /scans/{id}/export/{file}/download` without auth → HTTP 401; with `X-Cookie` + `X-API-Token` → HTTP 200.
- **Impact on CredFlow:** **None** — CredFlow always sends `X-Cookie` and `X-API-Token` on the download request. ✅

### 4. `POST /scans` requires X-API-Token (412 without it)
- **Empirical:** `POST /scans` without `X-API-Token` → HTTP 412 `{"error":"API is not available"}`; with token → 200.
- **Impact on CredFlow:** **None** — CredFlow always sets `X-API-Token` after login/token discovery. ✅

### 5. `GET /editor/template/list` (plural) errors
- **Empirical:** `GET /editor/template/list?type=scan` → `{"error":"Invalid 'id' field: invalid type 'string', expecting 'int'"}`. The correct endpoint is `GET /editor/scan/templates` (singular, works).
- **Impact on CredFlow:** **None** — CredFlow uses `/editor/scan/templates`. ✅

---

## Recommendations

1. **No urgent code change required** for the core scan lifecycle — create/launch/poll/export/delete/trash all work on 19.18.4.

2. **`plugins.families` regression — RESOLVED.** The root cause was the missing `X-API-Version: 2` request header (the web UI sends it; CredFlow did not). With the header, `plugins.families` is returned by editor endpoints and `plugins` payloads take effect in `POST /scans` and `POST /policies`. CredFlow now sends the header on every request. Verified end-to-end on the live server: `--disabled-families "Denial of Service"` produces a scan whose editor config shows `Denial of Service: {status: "disabled"}`.

3. **Do not add UUID-format validation.** Template UUIDs are now 52-char; keep treating them as opaque strings. If any future code validates UUID format, it must accept the 52-char form.

4. **Keep sending `X-Cookie` + `X-API-Token` on all requests**, including downloads — this is now mandatory (401 without auth on downloads).

5. **Version detection:** `check_connection()` reads `server_version` (now `19.18.4`). If any logic branches on version, note that the engine version (19.x) and UI version (10.12.x) differ; prefer `nessus_ui_version` for UI-feature gating or document the mapping.

6. **Monitor official docs** for a formal 19.x API changelog. As of 2026-08-30, official release notes and the lifecycle matrix still use 10.x numbering; the 19.x engine scheme is not yet reflected in public documentation.

---

## Sources

**Official documentation:**
- [Tenable Nessus 2026 Release Notes](https://docs.tenable.com/release-notes/Content/nessus/2026.htm) — 10.12.0 unauthenticated-download change; latest 10.12.4.
- [Tenable Nessus 2025 Release Notes](https://docs.tenable.com/release-notes/Content/nessus/2025.htm)
- [Tenable Software Release Lifecycle Matrix](https://docs.tenable.com/pdfs/product-lifecycle-management/tenable-software-release-lifecycle-matrix.pdf) — 10.x versioning.
- [List templates (developer.tenable.com)](https://developer.tenable.com/reference/editor-list-templates) — 52-char template UUIDs.
- [Export scan (developer.tenable.com)](https://developer.tenable.com/reference/scans-export-request) — export formats incl. `db` with `password`.
- [Scan Exports and Reports (Nessus 10.12 User Guide)](https://docs.tenable.com/nessus/Content/ScanReportFormats.htm) — Nessus DB requires password.
- [Export a Scan (Nessus 10.12 User Guide)](https://docs.tenable.com/nessus/Content/ExportAScan.htm)
- [Tenable Developer Portal Welcome](https://developer.tenable.com/docs/welcome) — cloud API base URL / auth scheme.
- [pyTenable Nessus Editor API](https://pytenable.readthedocs.io/en/stable/api/nessus/editor.html) — local editor endpoint paths (`editor/{type}/templates`, `editor/{type}/templates/{uuid}`, `editor/{type}/{id}`).

**Empirical (live server `https://192.168.1.116:8834`, Nessus Professional 19.18.4 build 20038):**
- `GET /server/properties` → `server_version: 19.18.4`, `server_build: 20038`, `nessus_ui_version: 10.12.4`.
- `GET /nessus6.js` (no auth) → 4 `value:function(){return"..."}` matches; real token is the 36-char UUID.
- `GET /editor/scan/templates` → 21 templates, all 52-char UUIDs.
- `GET /editor/scan/templates/{uuid}` and `GET /editor/scan/{id}` → `plugins` key is `None`.
- `POST /scans` (with 52-char uuid + settings + credentials + plugins) → 200; without X-API-Token → 412.
- `POST /scans/{id}/launch` → `{"scan_uuid": ...}`.
- `GET /scans/{id}` → `info.status` polling works.
- `POST /scans/{id}/export` (nessus + db w/ password) → `{"file": <id>, "token": ...}`; status → `ready`; download with auth → 200, without auth → 401.
- `DELETE /scans/{id}` → 200 (inactive) / 409 (active).
- `PUT /scans/{id}/folder` `{"folder_id":2}` → 200 (trash).
- `GET /folders` → Trash id 2, My Scans id 3.
- `GET /editor/template/list` → `Invalid 'id' field` error.
