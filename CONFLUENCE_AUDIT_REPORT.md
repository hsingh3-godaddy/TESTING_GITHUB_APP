# Confluence Connector — Independent Production Readiness Audit

**Date:** 2026-03-17
**Auditor:** Independent External Code Review
**Scope:** All files changed on branch `rtm-confluence-connector` vs `main` (~2,900 lines across 10 files)
**Application Context:** GDSec360 is a production security/threat-modeling tool that handles OAuth tokens and connects to customer Confluence Cloud instances. The security bar for a security tool must be absolute.

---

## 1. VERDICT SUMMARY

**PRODUCTION READY: ❌ NO**

| Metric | Value |
|--------|-------|
| **Overall Score** | **28 / 100** |
| **Critical Blockers** | 6 |
| **High Priority Issues** | 8 |
| **Medium Priority Issues** | 8 |
| **Low Priority Issues** | 5 |
| **Test Coverage** | **0%** (zero test files exist) |

---

## 2. BLOCKER ISSUES (Must fix before ANY deployment)

| # | Issue | File | Risk | Effort |
|---|-------|------|------|--------|
| PROD-001 | Hardcoded session signing secret | `handlers/confluenceHandlers.go:45` | CRITICAL | 1 hr |
| PROD-002 | OAuth session files in world-readable `/tmp` | `handlers/confluenceHandlers.go:41` | CRITICAL | 1 hr |
| PROD-003 | `validateImageMagicBytes()` defined but NEVER called — dead code | `connectors/confluence_validate.go:245` | CRITICAL | 30 min |
| PROD-004 | No request body size limits on POST endpoints (OOM/DoS) | `handlers/confluenceHandlers.go:415,490` | CRITICAL | 1 hr |
| PROD-005 | XSS via Confluence page title in frontend `innerHTML` | `templates/rtm.html` (multiple) | CRITICAL | 2 hrs |
| PROD-006 | Image proxy passes Content-Type without validation (XSS) | `handlers/confluenceHandlers.go:587` | CRITICAL | 1 hr |

---

## 3. DETAILED FINDINGS

---

### 🔴 PROD-001 — Hardcoded Session Signing Secret (CRITICAL)

**Category:** Security
**File:** `handlers/confluenceHandlers.go:45`
**Also:** `handlers/auth.go:27` (same UUID)

**Problem:** The FilesystemStore that holds Confluence OAuth access tokens is signed with a UUID hardcoded in source code. Anyone with repository access can forge session cookies containing arbitrary OAuth tokens.

**Current Code:**
```go
confluenceSessionStore = sessions.NewFilesystemStore(sessionDir, []byte("3107638e-f80f-11ef-bd97-56fdc237bf29"))
```

**Why This Fails in Production:**
An attacker (or any employee/CI system with repo access) forges a session cookie with `confluence_access_token` and `confluence_cloud_id` values, then calls any Confluence endpoint to read customer data. This is a **complete session hijacking** vulnerability.

**Production-Ready Fix:**
```go
sessionKey := config.Config.OktaConfig.SessionKey
if sessionKey == "" {
    sessionKey = os.Getenv("SESSION_SECRET")
}
if sessionKey == "" {
    panic("SESSION_SECRET or OktaConfig.SessionKey must be set")
}
confluenceSessionStore = sessions.NewFilesystemStore(sessionDir, []byte(sessionKey))
```

**Verification:** Remove the hardcoded UUID, set env var, confirm sessions work and old cookies are rejected.

---

### 🔴 PROD-002 — OAuth Tokens Stored in World-Readable `/tmp` (CRITICAL)

**Category:** Security
**File:** `handlers/confluenceHandlers.go:41`

**Problem:** Session files containing Confluence OAuth access tokens and refresh tokens are stored in `/tmp/gdsec360-sessions/`. On shared infrastructure, containers with shared `/tmp` volumes, or any multi-tenant environment, other processes can read these files and steal tokens.

**Current Code:**
```go
sessionDir := filepath.Join(os.TempDir(), "gdsec360-sessions")
```

**Why This Fails in Production:**
On ECS/EKS with shared volumes, sidecar containers, or any environment with multiple processes running as the same user, plaintext OAuth tokens are exposed.

**Production-Ready Fix:**
```go
sessionDir := os.Getenv("SESSION_STORE_DIR")
if sessionDir == "" {
    sessionDir = "/var/lib/gdsec360/sessions"
}
if err := os.MkdirAll(sessionDir, 0700); err != nil {
    panic("failed to create session directory: " + err.Error())
}
```

**Verification:** Verify sessions work from new directory. Check `ls -la` permissions.

---

### 🔴 PROD-003 — `validateImageMagicBytes()` Is Dead Code (CRITICAL)

**Category:** Security
**Defined:** `connectors/confluence_validate.go:245`
**Should be called in:** `connectors/confluence.go:543-555`

**Problem:** A well-written magic-byte validation function exists to prevent polyglot attacks (HTML disguised as PNG). However, it is **NEVER called anywhere**. The entire defense is dead code. Images are downloaded and base64-encoded without any content verification.

**Current Code (confluence.go:543-555):**
```go
imgData, err := c.doDownload(ctx, resolvedURL)
if err != nil {
    filtered++
    continue
}
// ⚠️ NO MAGIC BYTE VALIDATION HERE
images = append(images, FetchedImage{
    Filename:    att.Title,
    ContentType: mediaType,
    Base64Data:  base64.StdEncoding.EncodeToString(imgData),
})
```

**Why This Fails in Production:**
An attacker uploads an HTML file with `.png` extension to a Confluence page. The connector downloads it, base64-encodes it, and passes it to the frontend where it could be decoded and rendered, enabling XSS.

**Production-Ready Fix:**
```go
imgData, err := c.doDownload(ctx, resolvedURL)
if err != nil {
    filtered++
    continue
}

// Verify magic bytes match declared Content-Type
if !validateImageMagicBytes(imgData, mediaType) {
    filtered++
    logger.Warnf("confluence: skipping %q (magic bytes don't match declared type %s)", att.Title, mediaType)
    continue
}

images = append(images, FetchedImage{ /* ... */ })
```

**Verification:** Upload a `.html` file renamed to `.png` to a Confluence page. Verify the connector rejects it.

---

### 🔴 PROD-004 — No Request Body Size Limits on POST Endpoints (CRITICAL)

**Category:** Security / DoS
**Files:** `handlers/confluenceHandlers.go:415,490`

**Problem:** Both `/api/confluence/fetch` and `/api/confluence/summarize` decode JSON request bodies with no size limit. The summarize endpoint accepts `images: []FetchedImage` with base64 data — an attacker can POST gigabytes, causing OOM and crashing the server for all users.

**Current Code:**
```go
json.NewDecoder(r.Body).Decode(&req)
```

**Production-Ready Fix:**
```go
// For /api/confluence/fetch (1 MB is plenty for a URL)
r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024)

// For /api/confluence/summarize (50 MB for content + images)
r.Body = http.MaxBytesReader(w, r.Body, 50*1024*1024)

if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    http.Error(w, "Request body too large or invalid", http.StatusBadRequest)
    return
}
```

**Verification:** `curl -X POST --data-binary @/dev/urandom http://localhost:8080/api/confluence/summarize` — should get 400.

---

### 🔴 PROD-005 — XSS via Confluence Page Title in Frontend (CRITICAL)

**Category:** Security
**File:** `templates/rtm.html` (multiple locations in innerHTML assignments)

**Problem:** The Confluence page title and image filenames are inserted directly into `innerHTML` without HTML escaping. An attacker who controls a Confluence page title can execute arbitrary JavaScript in every user's browser.

**Current Code (appears at ~5 locations):**
```javascript
statusDiv.innerHTML = '<strong>' + confluenceData.title + '</strong>';
// Also: img.filename in renderImageGrid()
```

**Why This Fails in Production:**
A Confluence page titled `<img src=x onerror=alert(document.cookie)>` executes JavaScript when any user fetches that page. This steals Okta JWT tokens, Confluence OAuth sessions, etc.

**Irony:** Line 623 correctly escapes content with `.replace(/</g, '&lt;')`, proving the developer knows about XSS but missed it in other locations.

**Production-Ready Fix:**
```javascript
function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}
// Use everywhere:
statusDiv.innerHTML = '<strong>' + escapeHtml(confluenceData.title) + '</strong>';
```

**Verification:** Create a Confluence page with title `<script>alert(1)</script>`. Fetch it. Verify it renders as text.

---

### 🔴 PROD-006 — Image Proxy Content-Type Passthrough (XSS) (CRITICAL)

**Category:** Security
**File:** `handlers/confluenceHandlers.go:587-591`

**Problem:** The image proxy streams Confluence responses to the browser, passing through whatever `Content-Type` Confluence returns. If Confluence returns `text/html` (error page or malicious file), the browser renders it as HTML in the application's origin.

**Current Code:**
```go
if ct := resp.Header.Get("Content-Type"); ct != "" {
    w.Header().Set("Content-Type", ct)
}
io.Copy(w, io.LimitReader(resp.Body, 10*1024*1024))
```

**Production-Ready Fix:**
```go
ct := resp.Header.Get("Content-Type")
if !strings.HasPrefix(ct, "image/") {
    http.Error(w, "Non-image content type rejected", http.StatusBadRequest)
    return
}
w.Header().Set("Content-Type", ct)
w.Header().Set("Content-Disposition", "inline")
w.Header().Set("X-Content-Type-Options", "nosniff")
io.Copy(w, io.LimitReader(resp.Body, 10*1024*1024))
```

**Verification:** Test image proxy with a URL returning `text/html`. Verify it's rejected.

---

### 🟠 PROD-007 — Confluence OAuth Endpoints Not Behind Okta Auth (HIGH)

**Category:** Security
**File:** `main.go:310-311`

**Problem:** `/auth/confluence/login` and `/auth/confluence/callback` use only tracing middleware, no `OktaJWTWithRBACMiddleware`. Any unauthenticated user on the network can initiate OAuth flows and store Confluence tokens in server-side sessions.

**Current Code:**
```go
http.Handle("/auth/confluence/login", wrapHandlerFuncWithTraceAndLogging(handlers.ConfluenceAuthLoginHandler))
http.Handle("/auth/confluence/callback", wrapHandlerFuncWithTraceAndLogging(handlers.ConfluenceAuthCallbackHandler))
```

**Fix:** Add `OktaJWTWithRBACMiddleware`. The callback needs special handling since the redirect from Atlassian won't carry the JWT cookie — consider a session-based check that verifies the user was logged in when they started the flow.

---

### 🟠 PROD-008 — Image Proxy Endpoint Not Behind Okta Auth (HIGH)

**Category:** Security
**File:** `main.go:320`

**Problem:** `/api/confluence/image-proxy` has no Okta JWT middleware. Comment says "browser img tags can't send Authorization headers" — this is true, but means any user on the network who obtains a Confluence session cookie can proxy unlimited requests to `*.atlassian.net`.

**Fix:** Implement signed-URL scheme (HMAC-verified temporary URLs) or require a nonce/CSRF token validated against the Okta session.

---

### 🟠 PROD-009 — Sensitive Data Logged at INFO Level (HIGH)

**Category:** Security
**Files:** `connectors/confluence.go`, `connectors/caas_client.go`

**Problem:** Debug-level information logged at INFO level throughout. In production, every request will log:

| File:Line | What's Leaked |
|-----------|--------------|
| `confluence.go:160` | baseURL with cloudID (customer instance identifier) |
| `confluence.go:255` | OAuth Bearer token usage with URL and cloudID |
| `caas_client.go:203` | First 40 chars of SSO JWT token |
| `caas_client.go:355` | Authorization header with token prefix AND suffix |
| `caas_client.go:399-401` | Raw CaaS response bodies (may contain customer data) |
| `confluence.go:427` | First 500 chars of raw attachment API response |

**Fix:** Change all `logger.Infof("... [DEBUG] ...")` to `logger.Debugf(...)`. Remove token previews entirely.

---

### 🟠 PROD-010 — CaaS Client Hardcoded to Dev Environment (HIGH)

**Category:** Configuration
**Files:** `config/config.go:125`, `connectors/caas_client.go:188`

**Problem:**
1. CaaS API server defaults to `https://caas.api.dev-godaddy.com`
2. `getSSOToken()` hardcodes `--environment dev --cacheName dev`
3. Neither can be overridden via config for the ssojwt call

**Fix:**
```go
env := config.GetCurrentEnv()
cmd := exec.CommandContext(ctx, "ssojwt", "--environment", env, "--cacheName", env, "default")
```

---

### 🟠 PROD-011 — No Rate Limiting on Confluence or CaaS Endpoints (HIGH)

**Category:** Security / Cost
**Files:** All Confluence routes in `main.go`

**Problem:** `/api/confluence/fetch`, `/api/confluence/summarize`, and `/api/confluence/image-proxy` have no rate limiting. The summarize endpoint calls a paid AI service (CaaS) — an attacker can drain AI budgets or DoS the application.

**Fix:** Add per-user/per-IP rate limiting middleware.

---

### 🟠 PROD-012 — Error Messages Expose Internal Details (HIGH)

**Category:** Security
**File:** `handlers/confluenceHandlers.go:119,513`

**Current Code:**
```go
http.Error(w, fmt.Sprintf("Atlassian authorization failed: %s - %s", errParam, errDesc), http.StatusBadRequest)
http.Error(w, "Summarization failed: "+err.Error(), http.StatusBadGateway)
```

**Fix:** Log full error server-side. Return generic messages to clients.

---

### 🟠 PROD-013 — Session Store MaxLength(0) Removes Size Limit (HIGH)

**Category:** Security / DoS
**File:** `handlers/confluenceHandlers.go:46`

**Problem:** `confluenceSessionStore.MaxLength(0)` removes the default 4096-byte limit. Combined with filesystem storage, allows disk exhaustion.

**Fix:** `confluenceSessionStore.MaxLength(32768)`

---

### 🟠 PROD-014 — OAuth Client Secrets Not in AWS Secrets Manager (HIGH)

**Category:** Configuration
**File:** `config/secrets.go` (EnvironmentSecrets struct)

**Problem:** `CONFLUENCE_OAUTH_CLIENT_ID` and `CONFLUENCE_OAUTH_CLIENT_SECRET` are not in the `EnvironmentSecrets` struct. They can only come from env vars, bypassing the AWS Secrets Manager workflow.

**Fix:** Add to `EnvironmentSecrets` and `LoadConfigFromSecrets()`.

---

### 🟡 PROD-015 — Token Refresh Race Condition (MEDIUM)

**Category:** Reliability
**File:** `handlers/confluenceHandlers.go:367-388`

**Problem:** Concurrent requests detecting an expired token both call `refreshConfluenceToken()`. Atlassian invalidates the old refresh token on use — the second refresh fails.

**Fix:** Add `sync.Mutex` per session for token refresh serialization.

---

### 🟡 PROD-016 — Unbounded `io.ReadAll` on External Responses (MEDIUM)

**Category:** Security / DoS
**Files:** `handlers/confluenceHandlers.go:171,283,329`, `connectors/caas_client.go:390`

**Problem:** Multiple `io.ReadAll(resp.Body)` calls on Atlassian and CaaS API responses have no size limit. Malicious or malfunctioning upstream could cause OOM.

**Fix:** Use `io.ReadAll(io.LimitReader(resp.Body, maxBytes))` consistently.

---

### 🟡 PROD-017 — `convertStructuralHTML` Doesn't Handle Attributes (MEDIUM)

**Category:** Functionality
**File:** `connectors/confluence_validate.go:200-224`

**Problem:** `strings.NewReplacer` only matches bare `<h1>`. Confluence produces `<h1 class="..." id="...">` which won't match. Heading markers (`#`, `##`) are lost, degrading AI summarization quality.

**Fix:** Use regex: `(?i)<h1[^>]*>` → `\n# `

---

### 🟡 PROD-018 — No Session Expiry/Cleanup for Filesystem Sessions (MEDIUM)

**Category:** Reliability
**File:** `handlers/confluenceHandlers.go:41-46`

**Problem:** Session files accumulate indefinitely. No expiry enforcement, no cleanup goroutine, no max session limit.

**Fix:** Set `session.Options.MaxAge` and implement periodic cleanup.

---

### 🟡 PROD-019 — No CSRF Protection on Image Proxy (MEDIUM)

**Category:** Security
**File:** `handlers/confluenceHandlers.go:528`

**Problem:** GET-based endpoint. Cross-origin `<img>` tags can probe for active Confluence sessions.

**Fix:** Require CSRF token or use non-standard headers.

---

### 🟡 PROD-020 — Frontend Stores Sensitive Data in Global JS Variables (MEDIUM)

**Category:** Security
**File:** `templates/rtm.html`

**Problem:** `confluenceData` (full page content + base64 images) and `confluenceSummary` stay in global JS variables, accessible to browser extensions, XSS, dev tools.

**Fix:** Minimize data retention. Clear variables when not needed.

---

### 🟡 PROD-021 — No Timeout on Token Exchange HTTP Calls (MEDIUM)

**Category:** Reliability
**File:** `handlers/confluenceHandlers.go:161`

**Problem:** `http.Post(atlassianTokenURL, ...)` uses Go's default HTTP client with no timeout.

**Fix:** `(&http.Client{Timeout: 15 * time.Second}).Post(...)`

---

### 🟡 PROD-022 — CaaS Response Body Read Without Size Limit (MEDIUM)

**Category:** Security / DoS
**File:** `connectors/caas_client.go:390`

**Problem:** `rawBody.ReadFrom(resp.Body)` reads until EOF with no limit.

**Fix:** Use `io.LimitReader(resp.Body, 10*1024*1024)`.

---

### 🟢 PROD-023 — Auth Status Endpoint Leaks Cloud ID (LOW)

**File:** `handlers/confluenceHandlers.go:260`
Returns `cloud_id` in JSON. Reveals internal Atlassian infrastructure.
**Fix:** Return only `authenticated` and `expired`.

---

### 🟢 PROD-024 — Zero Unit or Integration Tests (LOW for initial deploy, MUST-FIX for production)

**Files:** None exist
Zero tests for URL validation, sanitization, magic bytes, OAuth flow, handlers, or CaaS client.
**Fix:** Write tests. Target >80% coverage. Priority: `validateConfluenceURL`, `sanitizeStorageFormat`, `validateImageMagicBytes`.

---

### 🟢 PROD-025 — Excessive Debug Logging with [DEBUG] Prefix (LOW)

**Files:** `connectors/confluence.go`, `connectors/caas_client.go`
20+ log statements use `logger.Infof("... [DEBUG] ...")`. Will flood production logs.
**Fix:** Replace with `logger.Debugf(...)`.

---

### 🟢 PROD-026 — Source Field Not Validated (LOW)

**File:** `models/rtmModels.go`
New `Source` field accepts any string. No validation.
**Fix:** Validate on handler side.

---

### 🟢 PROD-027 — First Accessible Resource Always Used (LOW)

**File:** `handlers/confluenceHandlers.go:306`
`fetchConfluenceCloudID` always returns `resources[0].ID`. Users with multiple Confluence sites can only access the first.
**Fix:** Allow user to select site, or match against URL domain.

---

## 4. ENVIRONMENT-SPECIFIC READINESS

| Environment | Ready | Blocking Issues |
|-------------|-------|-----------------|
| **DEV** | ⚠️ Conditional | PROD-001, 003, 005 are dangerous even in dev |
| **TEST** | ❌ No | All 6 critical blockers + zero tests |
| **STAGING** | ❌ No | Above + PROD-010 (hardcoded dev), PROD-014 (secrets) |
| **PRODUCTION** | ❌ No | All 27 issues must be addressed |

---

## 5. PRIORITIZED ACTION PLAN

### BEFORE GO-LIVE — Blockers (~2 days)

| Priority | Issue | File(s) | Effort |
|----------|-------|---------|--------|
| P0 | PROD-001: Replace hardcoded session secret | `handlers/confluenceHandlers.go` | 1 hr |
| P0 | PROD-002: Move session dir out of `/tmp` | `handlers/confluenceHandlers.go` | 1 hr |
| P0 | PROD-003: Call `validateImageMagicBytes()` | `connectors/confluence.go` | 30 min |
| P0 | PROD-004: Add `MaxBytesReader` to POST handlers | `handlers/confluenceHandlers.go` | 1 hr |
| P0 | PROD-005: Escape all `innerHTML` insertions | `templates/rtm.html` | 2 hrs |
| P0 | PROD-006: Validate Content-Type in image proxy | `handlers/confluenceHandlers.go` | 1 hr |
| P1 | PROD-007: Add auth to OAuth endpoints | `main.go` | 2 hrs |
| P1 | PROD-008: Secure image proxy endpoint | `main.go`, handlers | 2 hrs |
| P1 | PROD-009: Fix log levels, remove token logging | Multiple | 2 hrs |
| P1 | PROD-010: Fix hardcoded dev URLs | `caas_client.go`, `config.go` | 1 hr |
| P1 | PROD-012: Sanitize error messages | `handlers/confluenceHandlers.go` | 1 hr |
| P1 | PROD-013: Set session MaxLength | `handlers/confluenceHandlers.go` | 15 min |
| P1 | PROD-014: Add OAuth secrets to Secrets Manager | `config/secrets.go` | 1 hr |

### WEEK 1 POST-LAUNCH

| Priority | Issue | Effort |
|----------|-------|--------|
| P2 | PROD-011: Rate limiting | 4 hrs |
| P2 | PROD-015: Token refresh race condition | 2 hrs |
| P2 | PROD-016: LimitReader on all external reads | 1 hr |
| P2 | PROD-017: Fix convertStructuralHTML | 2 hrs |
| P2 | PROD-018: Session cleanup | 2 hrs |
| P2 | PROD-021: Timeouts on token exchange | 30 min |
| P2 | PROD-022: LimitReader on CaaS response | 30 min |

### TECHNICAL DEBT (30-60 days)

| Priority | Issue | Effort |
|----------|-------|--------|
| P3 | PROD-019: CSRF on image proxy | 2 hrs |
| P3 | PROD-020: Minimize global JS exposure | 2 hrs |
| P3 | PROD-024: Write tests (>80% coverage) | 3-5 days |
| P3 | PROD-025: Clean up debug logging | 1 hr |
| P3 | PROD-026: Validate Source field | 30 min |
| P3 | PROD-027: Multi-site support | 4 hrs |

---

## 6. VERIFICATION CHECKLIST

After implementing fixes:

- [ ] **PROD-001:** Start app with env var only — old hardcoded cookies must be rejected
- [ ] **PROD-003:** Upload renamed `.html` as `.png` to Confluence — connector must reject it
- [ ] **PROD-004:** POST oversized body to `/api/confluence/summarize` — must get 400
- [ ] **PROD-005:** Confluence page with title `<script>alert(1)</script>` — must render as text
- [ ] **PROD-006:** Image proxy with `text/html` response — must be rejected
- [ ] **PROD-009:** Run with INFO logging, grep for tokens — must find none
- [ ] **PROD-010:** Deploy to staging, verify CaaS uses staging URL and ssojwt uses correct env
- [ ] Run `go vet ./...` and `staticcheck ./...`
- [ ] Run full test suite with `go test ./connectors/... ./handlers/... -cover`

---

## 7. PENDING VULNERABILITIES (Still Open)

The following issues from the original audit have **NOT yet been fully resolved** and require attention before production deployment.

| # | Issue | Severity | File(s) | Status | Notes |
|---|-------|----------|---------|--------|-------|
| PROD-001 | Hardcoded session signing secret | CRITICAL | `handlers/confluenceHandlers.go:91` | **OPEN** | Session store still uses hardcoded UUID `3107638e-...`. Must read from env var or Secrets Manager. |
| PROD-002 | OAuth sessions in world-readable `/tmp` | CRITICAL | `handlers/confluenceHandlers.go:87` | **OPEN** | Session dir still defaults to `os.TempDir()`. Must use a secure, non-shared directory. |
| PROD-008 | Image proxy not behind Okta auth | HIGH | `main.go:323` | **OPEN** | `/api/confluence/image-proxy` still lacks Okta JWT middleware. Needs signed-URL or nonce scheme. |
| PROD-009 | Sensitive data logged at INFO level | HIGH | `connectors/confluence.go`, `connectors/caas_client.go` | **OPEN** | `[DEBUG]` messages at INFO level leak cloudIDs, URLs, and raw responses in production logs. |
| PROD-010 | CaaS client hardcoded to dev environment | HIGH | `config/config.go`, `connectors/caas_client.go` | **OPEN** | CaaS API defaults to `dev-godaddy.com`; ssojwt hardcodes `--environment dev`. |
| PROD-012 | Error messages expose internal details | HIGH | `handlers/confluenceHandlers.go:165,532` | **OPEN** | Atlassian error params and `err.Error()` returned to clients. |
| PROD-013 | Session store MaxLength(0) removes size limit | HIGH | `handlers/confluenceHandlers.go:92` | **OPEN** | `MaxLength(0)` allows unlimited session size — disk exhaustion risk. |
| PROD-014 | OAuth secrets not in AWS Secrets Manager | HIGH | `config/secrets.go` | **OPEN** | `CONFLUENCE_OAUTH_CLIENT_ID` / `CLIENT_SECRET` not in `EnvironmentSecrets` struct. |
| PROD-015 | Token refresh race condition | MEDIUM | `handlers/confluenceHandlers.go` | **OPEN** | No `sync.Mutex` per session for token refresh serialization. |
| PROD-018 | No session expiry/cleanup for filesystem sessions | MEDIUM | `handlers/confluenceHandlers.go` | **OPEN** | Session files accumulate indefinitely. No MaxAge or cleanup goroutine. |
| PROD-020 | Frontend stores sensitive data in global JS variables | MEDIUM | `templates/rtm.html` | **PARTIAL** | `confluenceData`/`confluenceSummary` nulled on error but not cleared after successful submission. |
| PROD-024 | Zero unit or integration tests | LOW | N/A | **OPEN** | No test files exist. Target >80% coverage. |
| PROD-025 | Excessive debug logging with [DEBUG] prefix | LOW | `connectors/confluence.go`, `connectors/caas_client.go` | **OPEN** | 20+ `logger.Infof("... [DEBUG] ...")` calls will flood production logs. |
| PROD-027 | First accessible resource always used | LOW | `handlers/confluenceHandlers.go:357` | **OPEN** | Multi-site users always get `resources[0]`. No site selection or URL-based matching. |

---

## 8. FIXED VULNERABILITIES (Resolved)

The following issues from the original audit have been **verified as fixed** in the current codebase on branch `rtm-confluence-connector`.

| # | Issue | Severity | Fix Location | How It Was Fixed |
|---|-------|----------|-------------|-----------------|
| PROD-003 | `validateImageMagicBytes()` was dead code | CRITICAL | `connectors/confluence.go:551-555` | Magic-byte validation now called immediately after `doDownload()`. Images failing verification are filtered out with a warning log. |
| PROD-004 | No request body size limits on POST endpoints | CRITICAL | `handlers/confluenceHandlers.go:418, 506` | `http.MaxBytesReader` applied: 1 MB limit on `/api/confluence/fetch`, 50 MB limit on `/api/confluence/summarize`. |
| PROD-005 | XSS via Confluence page title in innerHTML | CRITICAL | `templates/rtm.html:114-118` | `escapeHtml()` function defined and applied to all user-controlled strings (page titles, image filenames, error messages) before innerHTML insertion. |
| PROD-006 | Image proxy Content-Type passthrough (XSS) | CRITICAL | `handlers/confluenceHandlers.go:625-637` | Content-Type validated with `strings.HasPrefix(ct, "image/")`. Non-image types rejected. `X-Content-Type-Options: nosniff` header added. |
| PROD-007 | Confluence OAuth endpoints not behind Okta auth | HIGH | `main.go:313-314` | `/auth/confluence/login` wrapped with `OktaJWTWithRBACMiddleware`. Callback exempt (Atlassian redirect can't carry JWT) but protected by cryptographic state parameter validation. |
| PROD-011 | No rate limiting on Confluence/CaaS endpoints | HIGH | `handlers/confluenceHandlers.go:26-68` | Token-bucket rate limiter: 10 req/min per user, burst of 5. Applied to fetch (`:412`), summarize (`:500`), and image proxy (`:554`). |
| PROD-016 | Unbounded `io.ReadAll` on external responses | MEDIUM | Multiple files | `io.LimitReader` wraps all external response reads: token exchange (1 MB), cloud ID (1 MB), page content (5 MB), attachments (5 MB), image downloads (10 MB). |
| PROD-017 | `convertStructuralHTML` doesn't handle attributes | MEDIUM | `connectors/confluence_validate.go:201-249` | Replaced `strings.NewReplacer` with regex patterns using `[^>]*` to match tags with attributes (e.g., `<h1 class="..." id="...">`). |
| PROD-019 | No CSRF protection on image proxy | MEDIUM | `handlers/confluenceHandlers.go:559-571` | Validates `Sec-Fetch-Site` header (must be `same-origin` or `same-site`). Blocks requests with no `Sec-Fetch-Site` and no `Referer`. |
| PROD-021 | No timeout on token exchange HTTP calls | MEDIUM | `handlers/confluenceHandlers.go:207, 327` | Token exchange uses `&http.Client{Timeout: 15 * time.Second}`. Cloud ID fetch uses `Timeout: 10 * time.Second`. |
| PROD-022 | CaaS response body read without size limit | MEDIUM | `connectors/caas_client.go:391` | `rawBody.ReadFrom(io.LimitReader(resp.Body, 10<<20))` — capped at 10 MB. |
| PROD-023 | Auth status endpoint leaks cloud ID | LOW | `handlers/confluenceHandlers.go:311-315` | Response now returns only `authenticated`, `expired`, and `status`. `cloud_id` removed from JSON output. |
| PROD-026 | Source field not validated | LOW | `handlers/rtmHanlders.go:80-82` | Source field validated: must be empty string or `"confluence"`. Invalid values rejected with error. |

**Fixed: 13 / 27** | **Pending: 14 / 27** | **Last reviewed: 2026-03-19**
