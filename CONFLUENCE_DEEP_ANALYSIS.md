# Confluence Code Deep Analysis Report

## Overall Quality Score: 4/10

| Dimension | Score | Key Finding |
|-----------|-------|-------------|
| Security | 7/10 | Strong — SSRF, XSS, CSRF, magic bytes all solid |
| Architecture | 3/10 | God functions, no service layer, tight coupling |
| Error Handling | 4/10 | 4 inconsistent patterns, silent failures, ignored errors |
| Code Organization | 4/10 | Magic strings, duplication, 217-line functions |
| Testability | 0/10 | Zero test files across entire project (0 of 72 Go files) |
| Frontend | 2/10 | 880 lines inline JS, all inline CSS, global state pollution |

---

# PART 1: CONNECTORS LAYER ANALYSIS

## 1. `connectors/confluence.go` (814 lines)

### FUNCTION LENGTH VIOLATIONS

#### `fetchImages()` — 217 lines (lines 367-583) — CRITICAL

Single method does 6 separate responsibilities:
1. Fetches attachment list from API (network I/O)
2. Deduplicates by version number (data structure logic)
3. Filters by type allowlist (validation)
4. Filters by size bounds (validation)
5. Downloads actual image data (network I/O)
6. Validates magic bytes (security verification)

**Complexity indicators:**
- 4 nested loops (lines 445-455, 473-564)
- 8 separate `if` statements filtering (lines 487-533)
- 3 different error handling patterns within one method
- Cyclomatic complexity ~25 (should be <10)

**The filter loop (lines 473-564) — 91 lines of repeated pattern:**
```go
for _, att := range deduped {                      // Depth 1
    // ... metadata logging
    if !isAllowedImageType() {                     // Depth 3
        filtered++; continue
    }
    if !isAboveMinSize() {                         // Depth 3
        filtered++; continue
    }
    if fileSize > maxImageBytes {                  // Depth 3
        filtered++; continue
    }
    if dlLink == "" {                              // Depth 3
        filtered++; continue
    }
    // ... more if blocks with identical structure ...
    if !validateImageMagicBytes() {                // Depth 3
        filtered++; continue
    }
    images = append(...)                           // Finally adds image
}
```

**Should be split into:**
- `fetchAttachmentMetadata()` — API call only
- `deduplicateAttachments()` — pure data logic, easily testable
- `filterAttachments()` — validation pipeline
- `downloadAttachmentData()` — network I/O

#### `Fetch()` — 90 lines (lines 136-225)

Contains 9 sequential steps with no extraction:
- Line 140: Validates URL, extracts pageID
- Line 148: **Parses URL AGAIN** (already validated — redundant)
- Line 158: Builds baseURL
- Line 164-174: Checks credentials **AFTER** constructing URL (wrong order)
- Lines 178-225: Fetches page, sanitizes, extracts images, downloads

**Logic gap:** Credential check at line 164 happens AFTER URL work at line 158. If credentials are missing, error thrown after URL work already done. Should validate credentials FIRST.

#### `fetchPage()` — 76 lines (lines 283-358)

Should extract response parsing into separate helper.

#### `buildRequest()` — 37 lines (lines 241-277)

2 branches (OAuth vs Basic auth) each ~15 lines:
```go
if auth, ok := ConfluenceAuthFromContext(ctx); ok {
    req.Header.Set("Authorization", "Bearer "+auth.AccessToken)
    // ... OAuth headers
} else {
    credentials := base64.StdEncoding.EncodeToString(...)
    req.Header.Set("Authorization", "Basic "+credentials)
    // ... Basic auth headers
}
```
Could split into `setBearerAuth()` / `setBasicAuth()`.

### LINES-PER-FUNCTION BREAKDOWN

| Function | Lines | Status |
|----------|-------|--------|
| `Name()` | 1 | Excellent |
| `Validate()` | 5 | Excellent |
| `resolveBaseURL()` | 10 | Good |
| `Fetch()` | 90 | TOO LONG — Extract 5-6 helpers |
| `buildRequest()` | 37 | Borderline — Extract auth logic |
| `fetchPage()` | 76 | TOO LONG — Extract response parsing |
| `fetchImages()` | 217 | CRITICAL — Extract 4+ helpers |
| `buildImageDownloadURL()` | 33 | Acceptable |
| `doDownload()` | 31 | Acceptable |
| `extractReferencedImages()` | 13 | Good |
| `handleAPIError()` | 28 | Good |

### CODE DUPLICATION

**Status code handling duplicated 3 times:**

`fetchPage()` (lines 307-319):
```go
if resp.StatusCode != http.StatusOK {
    errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
    logger.Debugf(...)
    return "", "", c.handleAPIError("fetch_page", pageID, resp.StatusCode)
}
```

`fetchImages()` (lines 395-405):
```go
if resp.StatusCode != http.StatusOK {
    errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
    logger.Debugf(...)
    return nil, 0, c.handleAPIError("fetch_attachments", pageID, resp.StatusCode)
}
```

`doDownload()` (lines 638-643):
```go
if resp.StatusCode != http.StatusOK {
    errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))  // ← WHY 512 here but 1024 above?
    logger.Errorf(...)
    return nil, "", fmt.Errorf(...)
}
```

**All three follow the exact same pattern** — should be one `checkAPIResponse()` helper. Also note the inconsistent body limit: 1024 bytes in two places, 512 in the third.

### MAGIC STRINGS/NUMBERS

| Line | Hardcoded Value | Should Be |
|------|----------------|-----------|
| 120 | `"https://api.atlassian.com/ex/confluence/%s"` | Named constant `oauthProxyURLFmt` |
| 253 | `"Bearer "+auth.AccessToken` | `authSchemeBearer` constant |
| 285 | `"%s/wiki/api/v2/pages/%s?body-format=storage"` | Named constant `confluenceV2PagesPath` |
| 369 | `"%s/wiki/api/v2/pages/%s/attachments?limit=%d"` | Named constant `confluenceV2AttachmentsPath` |
| 592 | `"/wiki/rest/api/content/"` | Named constant `confluenceV1DownloadPath` |
| 311 | `io.LimitReader(resp.Body, 1024)` | Named constant `errBodyLimit` |
| 639 | `io.LimitReader(resp.Body, 512)` | Same constant (inconsistent!) |

### INCONSISTENT ERROR HANDLING — 4 Different Patterns

**Pattern 1: No context wrapping (line 144)**
```go
if err != nil {
    return nil, err  // No context — caller has no idea what failed
}
```

**Pattern 2: Wrapped with context (line 152)**
```go
if err != nil {
    return nil, fmt.Errorf("confluence: malformed URL: %w", err)  // Good
}
```

**Pattern 3: Double-logged (lines 299-301)**
```go
logger.Errorf("confluence: failed to fetch page %s: %v", pageID, err)
return "", "", fmt.Errorf("confluence: failed to fetch page: %w", err)
// Both logs AND wraps — handler will also log, causing triple-log
```

**Pattern 4: Silent error discard (lines 311, 397, 639)**
```go
errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))  // ReadAll error silently ignored
logger.Debugf(..., string(errBody), ...)
```

### LOGIC FLOW ISSUES

**`buildImageDownloadURL()` (lines 589-622) — Fall-through branching:**
```go
// Three branches that can FALL THROUGH instead of if/else-if/else:
if attachmentID != "" {
    return fmt.Sprintf(...)  // Branch 1
}
if strings.HasPrefix(downloadLink, "http") {
    // validate and return  // Branch 2
}
// implicit fallthrough to path resolution  // Branch 3
```
Should be explicit `if/else-if/else`.

**Image deduplication (lines 443-463):**
```go
latest := make(map[string]confluenceAttachment)
for _, att := range attachments {
    existing, found := latest[att.Title]
    if !found || att.Version.Number > existing.Version.Number {
        latest[att.Title] = att
    }
}
```
- If two versions have same number, first wins silently (no logging)
- No logging of dropped versions

### VARIABLE NAMING ISSUES

| Current | Should Be | Location |
|---------|-----------|----------|
| `dlLink` | `downloadLink` | line 479 |
| `att` | `attachment` | lines 445, 459, 473 |
| `latest` | `latestVersionMap` | line 443 |
| `m` | (acceptable for range) | line 671 |

### MISSING: No Retries for Transient Failures

- `fetchPage()` fails once, immediately returns error
- Single network blip causes entire fetch to fail
- No retry with backoff for 5xx errors from Confluence API
- Compare with `caas_client.go` which DOES have retries

---

## 2. `connectors/confluence_validate.go` (304 lines) — WELL-DESIGNED

This file is the best-structured in the codebase.

### POSITIVE ASPECTS
- Constants properly centralized (lines 17-28)
- Compiled regexes at init() (lines 44-49) — prevents recompilation
- Clear security intent in comments
- Magic byte validation is excellent polyglot attack prevention
- Single responsibility: Validation and sanitization only
- No external dependencies: Only stdlib

### MINOR ISSUES

**30 Regex Passes Per Sanitization (lines 200-255):**
```go
// structuralTagReplacements has 30+ compiled regexes
for _, r := range structuralTagReplacements {
    s = r.re.ReplaceAllString(s, r.repl)  // Called 30 times sequentially
}
// Complexity: O(n * 30) where n = HTML length
```
Could be more efficient with single regex + callback or HTML parser library.

**WEBP Magic Byte Validation — Missing Constants (lines 295-297):**
```go
if normalizedType == "image/webp" {
    return len(data) >= 12 && string(data[8:12]) == "WEBP"  // Magic numbers 8 and 12 unexplained
}
```
Should have named constants: `webpTagOffset = 8`, `webpTagEnd = 12`.

**Incomplete WEBP Validation:**
- Only validates offset 8-12 ("WEBP" signature)
- Doesn't verify RIFF file size at offset 4-8
- Full validation should check:
  1. Offset 0-4: "RIFF"
  2. Offset 4-8: file size (validate doesn't exceed available data)
  3. Offset 8-12: "WEBP"

---

## 3. `connectors/caas_client.go` (436 lines) — BUGS + STRUCTURAL ISSUES

### BUG: Parse Errors Treated as Retryable (lines 404-409) — CRITICAL

```go
if resp.StatusCode == http.StatusCreated {
    content, extractErr := extractCaaSContent(rawBody.Bytes())
    if extractErr != nil {
        logger.Errorf("[CaaS] Failed to extract content from 201 response: %v", extractErr)
        lastErr = fmt.Errorf("CaaS response parse error: %w", extractErr)
        continue  // ← RETRIES! But server returned 201 — same response each time!
    }
    return content, nil
}
```

**Problem:** If CaaS returns valid 201 but `extractCaaSContent` fails (malformed JSON), the code retries up to 3 times with the SAME malformed response. Parse errors are NOT transient — they will never succeed on retry.

**Fix:** Return error immediately instead of `continue`.

### BUG: `getSSOToken()` Ignores Parent Context (lines 185-186) — HIGH

```go
func getSSOToken() (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    // ← Creates NEW context from Background(), ignoring parent!
```

**Problem:** If the parent HTTP request has a 5-second timeout, this SSO call creates a new 15-second context that IGNORES the parent's cancellation. The SSO token fetch can run 15 seconds after the parent request has been cancelled.

**Fix:** Accept parent context: `func getSSOToken(ctx context.Context) (string, error)`

### Ignored `ReadFrom()` Error (line 390) — HIGH

```go
var rawBody bytes.Buffer
rawBody.ReadFrom(io.LimitReader(resp.Body, 10<<20))  // Error completely ignored!
```

**Fix:** `if _, err := rawBody.ReadFrom(...); err != nil { continue }`

### `Summarize()` is 142 Lines (lines 294-435) — CRITICAL

75-line retry loop at 4+ nesting levels:
```go
for attempt := 0; attempt < caasMaxRetries; attempt++ {     // Depth 1
    if attempt > 0 {                                          // Depth 2
        backoff := time.Duration(...)                        // Depth 3
        select {                                              // Depth 4
            case <-ctx.Done(): ...
            case <-time.After(backoff): ...
        }
    }
    req, err := http.NewRequestWithContext(...)              // Depth 2
    resp, err := c.httpClient.Do(req)                        // Depth 2
    if err != nil { ... continue }                           // Depth 3
    // ... 40 more lines of response handling
}
```

**Should be split into:**
- `buildCaaSRequest(text, images)` — payload construction
- `doWithRetry(ctx, req)` — retry loop with backoff
- `Summarize()` becomes thin ~20 line orchestrator

### 142-Line Hardcoded System Prompt (lines 27-168) — HIGH

```go
const summarizationSystemPrompt = `You are an expert security architect...
[142 lines of AI prompt text hardcoded as Go string constant]
...`
```

**Problems:**
- Requires recompilation to update prompt text
- Difficult to version control and review
- Not externalized to config/file

**Fix:** Use Go `//go:embed` to load from `connectors/prompts/summarization_system_prompt.md`

### `ssojwt` Hardcoded to Dev (line 189) — MEDIUM

```go
cmd := exec.CommandContext(ctx, "ssojwt", "--environment", "dev", "--cacheName", "dev", "default")
```

Should be configurable via `CaaSConfig.SSOEnvironment` and `CaaSConfig.SSOCacheName`.

### No Token Refresh on 401 — MEDIUM

Token obtained once at start of `Summarize()`. If token expires during retry loop, retries same expired token 3x. Should detect 401 and refresh.

### Magic String (line 376)

```go
req.Header.Set("Authorization", "sso-jwt "+token)  // "sso-jwt " hardcoded
```

### `extractCaaSError()` — Silent Failure (lines 268-283)

```go
func extractCaaSError(raw []byte) string {
    var resp map[string]any
    if err := json.Unmarshal(raw, &resp); err != nil {
        return ""  // Silent failure — caller won't know parsing failed
    }
    // ...
}
```

---

## 4. `connectors/connector.go` (104 lines) — WELL-DESIGNED

### POSITIVE ASPECTS
- Clear interface definition (lines 34-44)
- Single responsibility: Registry pattern only
- Thread-safe registry with RWMutex
- Good function lengths: All under 20 lines

### ISSUES

**HTTP Client Not Configured (lines 54-59):**
```go
func NewBaseConnector() BaseConnector {
    return BaseConnector{
        HTTPClient: &http.Client{
            Timeout: 30 * time.Second,
            // No Transport! Uses default with no connection pooling config
        },
    }
}
```

**Should be:**
```go
transport := &http.Transport{
    MaxIdleConns:        20,
    MaxIdleConnsPerHost: 10,
    IdleConnTimeout:     90 * time.Second,
}
httpClient := &http.Client{
    Timeout:   30 * time.Second,
    Transport: transport,
}
```

**`Register()` Called from `init()` with `Fatalf` (line 75):**
```go
if _, exists := registry[name]; exists {
    logger.Fatalf("connectors: duplicate connector registered: %s", name)  // Crashes app!
}
```
Should return error instead of crashing.

---

# PART 2: HANDLERS LAYER ANALYSIS

## 5. `handlers/confluenceHandlers.go` (618 lines)

### `init()` Starts Background Goroutine (lines 104-152) — HIGH

```go
func init() {
    // ... session store setup ...

    go func() {                                    // Goroutine runs FOREVER
        ticker := time.NewTicker(5 * time.Minute)
        for range ticker.C {                       // No way to stop
            // ... cleanup logic ...
        }
    }()
}
```

**Problems:**
1. Goroutine runs forever with no way to stop — no graceful shutdown
2. init() should not start goroutines — makes testing impossible
3. No context-based cancellation
4. If cleanup panics, goroutine dies silently

**Fix:** Extract to `StartConfluenceCleanup(ctx context.Context)` called from `main()`.

### Silently Ignored Errors — 3 Locations — HIGH

**Line 188 — OAuth login:**
```go
userEmail, _ := util.GetEmailFromJWT(r)  // Error ignored!
session.Values["user_email"] = userEmail  // Could store empty string
```

**Line 263 — Token exchange:**
```go
tokenReqBody, _ := json.Marshal(map[string]string{...})  // Marshal error ignored!
```

**Line 616 — Summarize response:**
```go
json.NewEncoder(w).Encode(map[string]string{"summary": summary})  // Encode error not checked!
```

### Token Store Lock Contention (lines 342-348, 367-369, 441-443, 452-454) — MEDIUM

```go
// Write path:
confluenceTokenStoreMu.Lock()
confluenceTokenStore[userEmail] = &confluenceTokenEntry{...}
confluenceTokenStoreMu.Unlock()

// Read path:
confluenceTokenStoreMu.RLock()
entry, ok := confluenceTokenStore[userEmail]
confluenceTokenStoreMu.RUnlock()
```

**Problem:** Single global `RWMutex` map for ALL users. With thousands of concurrent users, lock contention will be severe. Consider sharded map or Redis.

### Rate Limiter Falls Back to `r.RemoteAddr` (lines 483-490) — MEDIUM

```go
userKey, _ := util.GetEmailFromJWT(r)
if userKey == "" {
    userKey = r.RemoteAddr  // ← Spoofable behind proxy!
}
if !checkRateLimit("fetch:" + userKey) {
    http.Error(w, "Too many requests", http.StatusTooManyRequests)
    return
}
```

**Problem:** Behind load balancer/proxy (common in Kubernetes), `r.RemoteAddr` is the proxy IP, not the user's IP. Rate limiting becomes per-proxy instead of per-user.

**Fix:** Check `X-Forwarded-For` header (set by ALB) first.

### OAuth State Has No Timestamp Check (lines 251-256) — MEDIUM

```go
savedState, ok := session.Values["oauth_state"].(string)
if !ok || savedState == "" || savedState != state {
    http.Error(w, "Invalid state parameter", http.StatusBadRequest)
    return
}
delete(session.Values, "oauth_state")
// ← No expiry check! State never times out.
```

If attacker intercepts state before it's used, they can replay it indefinitely.

### Inconsistent Error Response Format — MEDIUM

**Some handlers return plain text:**
```go
http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)  // Plain text
```

**Others return JSON:**
```go
json.NewEncoder(w).Encode(map[string]string{"summary": summary})  // JSON
```

Frontend can't reliably parse errors. Should standardize on JSON:
```go
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(map[string]string{"error": message})
}
```

### Magic Strings in Handlers

| Line | String | Should Be |
|------|--------|-----------|
| 72 | `"https://auth.atlassian.com/authorize"` | Named constant |
| 73 | `"https://auth.atlassian.com/oauth/token"` | Named constant |
| 74 | `"https://api.atlassian.com/oauth/token/accessible-resources"` | Named constant |
| 202 | `"read:page:confluence read:content-details:confluence..."` | Named constant |
| 36-38 | `10.0 / 60.0`, `5.0` | Named constants with explanation |

---

## 6. `main.go` — Confluence Routes (lines 313-320)

### No Graceful Shutdown (lines 336-352) — HIGH

```go
server := &http.Server{
    Addr: ":8080",
    // No ReadTimeout, WriteTimeout, IdleTimeout!
    // No MaxHeaderBytes!
}
if config.Config.TLSConfig.Enabled {
    server.ListenAndServeTLS(...)  // Blocks forever, no signal handling
}
```

**Problems:**
1. No signal handling (SIGTERM crashes without cleanup)
2. Background goroutines not stopped
3. Active connections killed abruptly
4. No server timeouts — vulnerable to slowloris

**Fix:**
```go
server := &http.Server{
    Addr:              ":8080",
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      15 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    1 << 20,
    ReadHeaderTimeout: 5 * time.Second,
}

sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
go func() {
    <-sigChan
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    server.Shutdown(ctx)
}()
```

### Inconsistent Middleware Application

```go
// OAuth login — has Okta JWT middleware:
http.Handle("/auth/confluence/login", middleware.OktaJWTWithRBACMiddleware(...))

// Callback — NO auth (correct, but state validation is ONLY protection):
http.Handle("/auth/confluence/callback", wrapHandlerFuncWithTraceAndLogging(...))

// API — has Okta JWT:
http.Handle("/api/confluence/fetch", middleware.OktaJWTWithRBACMiddleware(...))
```

---

# PART 3: FRONTEND ANALYSIS

## 7. `templates/rtm.html` — Confluence JavaScript (985 lines total)

### Monolithic Architecture — CRITICAL

- HTML structure: ~100 lines
- CSS: ALL inline (no external stylesheet)
- JavaScript: **880 lines in single `<script>` block**
- Complete violation of separation of concerns

### Global Namespace Pollution (lines 105-111)

```javascript
let scanTable;                       // DataTable instance
let resultOpen = false;
let loadingTimer = null;
let confluenceData = null;           // Fetched Confluence page
let confluenceSummary = null;        // AI-generated summary
let selectedImageIndex = 0;          // Selected image index
let confluenceOAuthConnected = false; // OAuth connection status
```

7+ globals at module scope with no encapsulation, no state validation.

### HTML Generated via String Concatenation (lines 373-379)

```javascript
statusDiv.innerHTML =
  '<i class="fas fa-check-circle"></i> <strong>' + escapeHtml(confluenceData.title) + '</strong>' +
  '<span style="margin-left: 12px;">' +
    '<a href="#" onclick="previewConfluenceData(); return false;" ' +
    'style="display: inline-block; padding: 3px 10px; border-radius: 4px; ...">' +
    'Preview</a>' +
    // ... more concatenated HTML
```

**Problems:**
- Hard to read and maintain
- Inline `onclick` handlers in generated HTML
- Same style strings duplicated 4+ times
- Difficult to test

### Inline CSS Everywhere

Every element has inline `style=` attributes with 150+ character strings:
```html
<input type="text" id="confluenceUrl" style="flex: 1; height: 50px; padding: 0 10px;
border: 2px solid #e0e0e0; border-radius: 8px; font-size: 1.1rem; background: white;
box-sizing: border-box; min-width: 0;" />
```

Same button styles duplicated 4 times in different status bar states.

### Race Condition — Summarize vs Clear — HIGH

```javascript
function clearConfluenceData() {
    confluenceData = null;       // Clears data
    confluenceSummary = null;    // Clears summary
    // ... update DOM
}
```

If `summarizeConfluenceData()` is in flight when `clearConfluenceData()` runs, the summary callback will try to write to UI elements that have been hidden/cleared.

**Fix:** Use `AbortController` to cancel in-flight requests on clear.

### No Duplicate-Click Prevention — MEDIUM

```javascript
// Line 34:
<button onclick="fetchConfluenceData()">Fetch</button>

// In fetchConfluenceData(), button disabled AFTER async call starts:
const btn = document.getElementById('confluence-fetch-btn');
btn.disabled = true;  // ← Too late! Multiple clicks already queued
```

### Polling Loop Without Backoff (lines 265-269)

```javascript
setInterval(() => {
    if (!resultOpen) {
        checkAuthAndProceed(fetchScanJobs);
    }
}, 2000);  // Every 2 seconds FOREVER — even when page is inactive
```

No request deduplication, no backoff, no visibility check.

### `sessionStorage` Stores Confluence URLs (lines 210-213, 311-312) — LOW

```javascript
sessionStorage.setItem('confluence_pending_url', confluenceUrl);
// ... after OAuth redirect:
const pendingUrl = sessionStorage.getItem('confluence_pending_url');
```

Could leak internal Confluence page IDs across page navigations.

### XSS Prevention — GOOD

```javascript
function escapeHtml(text) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}
```

- `escapeHtml()` is used consistently before all `innerHTML` injections
- Markdown renderer escapes input first (line 131)
- All user-controlled strings are escaped

### Error Handling — PRESENT BUT INCOMPLETE

```javascript
try {
    const response = await fetch('/api/confluence/fetch', { ... });
    if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
    // ... process
} catch (error) {
    if (error.name === 'AbortError') return;
    showToast('Error: ' + error.message, 'error');
}
```

**Good:** Try/catch around async operations, HTTP error checking, user-facing error messages.

**Issues:**
- Silent fallback on auth check failure (line 341-342): `catch (err) { // Fall through }`
- No timeout handling for long-running operations
- FileReader errors only logged, not shown to user
- No retry logic for failed API calls

---

# PART 4: PROJECT STRUCTURE

### Test Coverage: ZERO

- 0 of 72 Go files have corresponding `*_test.go`
- No unit tests for handlers, connectors, models
- No integration tests
- No frontend tests

### Filename Typo

`handlers/rtmHanlders.go` should be `handlers/rtmHandlers.go`

### Directory Structure (Good)

```
connectors/     — Confluence and CaaS integrations
handlers/       — HTTP route handlers (20+ files)
middleware/     — Auth, RBAC, logging, cache control
models/         — Data models (9 files)
templates/      — HTML templates (21 files)
static/         — CSS and JavaScript (29 files)
config/         — Configuration management
db/             — Database operations
util/           — Utilities
scripts/        — Helper scripts
```

### CI/CD (Good)

18 GitHub Actions workflows including dev/prod deployment, RTM pipelines, Lambda builds.

---

# SUMMARY: Issues by Severity

| Severity | Count | Key Examples |
|----------|-------|--------------|
| **CRITICAL** | 6 | `fetchImages()` 217 lines, `Summarize()` 142 lines, parse error retry bug, zero tests, monolithic 880-line frontend JS, no graceful shutdown |
| **HIGH** | 12 | Context override bug, ignored ReadFrom error, init() goroutine, 3 silently ignored errors, no HTTP retries, inline CSS duplication, race condition, token store contention |
| **MEDIUM** | 18 | Magic strings/numbers, DRY violations, inconsistent error patterns, rate limiter spoofable, OAuth state no expiry, inconsistent error responses, no connection pooling |
| **LOW** | 7 | Variable naming, regex inefficiency, sessionStorage privacy, incomplete WEBP validation |
| **TOTAL** | **43** | |

---

# SECURITY — What's GOOD

Despite the code quality issues, the security implementation is solid:

- **SSRF Prevention:** HTTPS-only, domain allowlist (*.atlassian.net), path validation
- **XSS Prevention:** 9-step HTML sanitization pipeline, event handler stripping, `escapeHtml()` used consistently
- **CSRF Protection:** Crypto-random state parameter in OAuth flow
- **Image Security:** Magic byte validation (polyglot prevention), type allowlist, size limits
- **Token Security:** Server-side memory store (never in cookies), per-user OAuth tokens
- **Rate Limiting:** Token bucket per user (10 req/min, burst 5)
- **Audit Logging:** `[AUDIT]` prefixed entries for security-relevant operations
- **Session Security:** HttpOnly, Secure, SameSite=Lax, 5-min TTL on OAuth cookies
