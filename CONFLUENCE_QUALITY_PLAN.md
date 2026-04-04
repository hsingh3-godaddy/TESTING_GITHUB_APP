# Confluence Code Quality Improvement Plan

## Context

The Confluence integration code works functionally (OAuth 2.0 3LO, page fetching, image pipeline, AI summarization) and has solid security fundamentals (SSRF prevention, XSS sanitization, CSRF protection, magic byte validation). However, deep analysis revealed significant code quality issues that need to be addressed to make this a production-grade, maintainable codebase.

---

## Current Quality Assessment

| Dimension | Score | Key Finding |
|-----------|-------|-------------|
| Security | 7/10 | Strong — best part of the codebase |
| Architecture | 3/10 | God functions, no service layer, tight coupling |
| Error Handling | 4/10 | 4 inconsistent patterns, silent failures |
| Code Organization | 4/10 | Magic strings, duplication, 217-line functions |
| Testability | 0/10 | Zero test files across entire project |
| Frontend | 2/10 | 880 lines inline JS, all inline CSS, global state |

---

## Files in Scope

| File | Lines | Role |
|------|-------|------|
| `connectors/confluence.go` | 814 | Core Confluence API client |
| `connectors/confluence_validate.go` | 304 | Validation & sanitization pipeline |
| `connectors/caas_client.go` | 436 | AI summarization client (CaaS) |
| `connectors/connector.go` | 104 | Connector framework & registry |
| `handlers/confluenceHandlers.go` | 618 | OAuth flow + fetch/summarize endpoints |
| `templates/rtm.html` | 985 | Frontend (Confluence JavaScript section) |
| `main.go` | 354 | Routes (Confluence section only) |

---

## Detailed Findings

### A. CONNECTORS LAYER

#### `connectors/confluence.go` — God Functions & Duplication

**Critical: `fetchImages()` is 217 lines (lines 367-583)**
- Single function does 6 separate responsibilities:
  1. Fetches attachment list from API (network I/O)
  2. Deduplicates by version number (data structure logic)
  3. Filters by type allowlist (validation)
  4. Filters by size bounds (validation)
  5. Downloads actual image data (network I/O again)
  6. Validates magic bytes (security verification)
- Cyclomatic complexity ~25 (should be <10)
- 8 separate `if` blocks with `filtered++; continue` pattern repeated identically
- 4 nested loops

**High: `Fetch()` is 90 lines (lines 136-225)**
- 9 sequential steps that could each be 5-10 line helpers
- URL parsed twice — once in `validateConfluenceURL()`, again on line 148 (redundant)
- Credential check (line 164) happens AFTER URL construction instead of before
- If credentials are missing, error is thrown after URL work is already done

**High: Code Duplication**
- Status code handling duplicated in `fetchPage()`, `fetchImages()`, `doDownload()` — all three follow the same pattern: check StatusCode → read error body → call `handleAPIError()`
- Response body limit inconsistent: 1024 bytes in two places, 512 in another (no reason for difference)
- Logging patterns duplicated with minor variations

**Medium: Magic Strings/Numbers**
| Location | Hardcoded Value | Should Be |
|----------|----------------|-----------|
| Line 120 | `"https://api.atlassian.com/ex/confluence/%s"` | Named constant |
| Line 253 | `"Bearer "` | `authSchemeBearer` constant |
| Line 285 | `"/wiki/api/v2/pages/%s?body-format=storage"` | Named constant |
| Line 369 | `"/wiki/api/v2/pages/%s/attachments?limit=%d"` | Named constant |
| Line 592 | `"/wiki/rest/api/content/"` | Named constant |

**Medium: Inconsistent Error Handling — 4 Different Patterns Found**
1. `return nil, err` — no context wrapping (line 144)
2. `return nil, fmt.Errorf("confluence: ...: %w", err)` — wrapped with context (line 152)
3. `logger.Errorf(...); return ..., fmt.Errorf(...)` — double-logged (line 299-301)
4. `errBody, _ := io.ReadAll(...); logger.Debugf(...)` — silent `ReadAll` error discard (lines 311, 397, 639)

**Low: Variable Naming**
- `dlLink` → should be `downloadLink`
- `att` → should be `attachment`
- `latest` → should be `latestVersionMap`

**Missing: No Retries for Transient Failures**
- `fetchPage()` fails once, returns error — single network blip causes entire fetch to fail
- No retry with backoff for 5xx errors from Confluence API

---

#### `connectors/confluence_validate.go` — Well-Designed (Minor Issues)

This file is the best-structured in the codebase.

**Minor: 30 Regex Passes Per Sanitization**
- `structuralTagReplacements` contains 30+ compiled regexes
- Each `convertStructuralHTML()` call loops through ALL 30 — O(n × 30)
- Could be more efficient but acceptable for current scale

**Minor: WEBP Magic Byte Constants Missing**
- Offsets `8:12` hardcoded without explanation
- Should have named constants: `webpTagOffset`, `webpTagEnd`

**Minor: Incomplete WEBP Validation**
- Only validates offset 8-12 ("WEBP" signature)
- Doesn't verify RIFF file size at offset 4-8
- Could accept truncated WEBP files

---

#### `connectors/caas_client.go` — Bugs + Structural Issues

**BUG (Critical): Parse Errors Treated as Retryable (line ~408)**
```go
if resp.StatusCode == http.StatusCreated {
    content, extractErr := extractCaaSContent(rawBody.Bytes())
    if extractErr != nil {
        lastErr = fmt.Errorf("CaaS response parse error: %w", extractErr)
        continue  // ← RETRIES 3x with same bad response!
    }
}
```
- If CaaS returns valid 201 with malformed content, retries up to 3 times with the SAME malformed response
- Parse errors are NOT transient — should fail immediately

**BUG (High): `getSSOToken()` Ignores Parent Context (line ~186)**
```go
ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
```
- Creates new context from `Background()`, ignoring parent's cancellation/timeout
- If parent HTTP request has 5s timeout, this SSO call can run for 15s beyond it
- Should derive from parent: `context.WithTimeout(ctx, 15*time.Second)`

**High: `Summarize()` is 142 Lines**
- 75-line retry loop at 4+ nesting levels
- Handles: auth, request construction, content building, marshaling, retry loop
- Should be split into `buildCaaSRequest()`, `doWithRetry()`, and thin `Summarize()` orchestrator

**High: Ignored `ReadFrom()` Error (line 390)**
```go
rawBody.ReadFrom(io.LimitReader(resp.Body, 10<<20))  // error ignored!
```

**High: 142-Line Hardcoded System Prompt (lines 27-168)**
- Entire AI prompt is a string constant in Go source
- Requires recompilation to update
- Should be externalized to embedded file

**Medium: No Token Refresh on 401**
- Token obtained once at start of `Summarize()`
- If token expires mid-retry, retries same expired token 3x
- Should detect 401 and refresh

**Medium: `ssojwt` Hardcoded to Dev Environment (line 189)**
```go
cmd := exec.CommandContext(ctx, "ssojwt", "--environment", "dev", "--cacheName", "dev", "default")
```
- Should be configurable via `CaaSConfig`

---

#### `connectors/connector.go` — Well-Designed (Minor Issues)

**Medium: HTTP Client Not Configured**
```go
HTTPClient: &http.Client{Timeout: 30 * time.Second}  // bare default
```
- No connection pooling, no keep-alive tuning
- Should configure `http.Transport` with `MaxIdleConns`, `MaxIdleConnsPerHost`, `IdleConnTimeout`

**Low: `Register()` Called from `init()` with `Fatalf` on Duplicate**
- Should return error instead of crashing
- Registration from `init()` creates unconfigured HTTP clients before config is loaded

---

### B. HANDLERS LAYER

#### `handlers/confluenceHandlers.go`

**High: `init()` Starts Background Goroutine (lines 104-152)**
- Cleanup goroutine runs forever with no way to stop it
- No graceful shutdown support
- Makes testing impossible
- Should be extracted to `StartConfluenceCleanup(ctx)` called from `main()`

**High: Silently Ignored Errors in 3 Places**
| Line | Code | Issue |
|------|------|-------|
| 188 | `userEmail, _ := util.GetEmailFromJWT(r)` | Error ignored during OAuth login |
| 263 | `tokenReqBody, _ := json.Marshal(...)` | Marshal error ignored |
| 616 | `json.NewEncoder(w).Encode(...)` | Encode error not checked |

**Medium: Inconsistent Error Response Format**
- Some handlers: `http.Error(w, "...", statusCode)` — plain text
- Some handlers: `json.NewEncoder(w).Encode(map[string]string{...})` — JSON
- Frontend can't reliably parse errors

**Medium: Rate Limiter Falls Back to `r.RemoteAddr`**
```go
userKey, _ := util.GetEmailFromJWT(r)
if userKey == "" {
    userKey = r.RemoteAddr  // spoofable behind proxy!
}
```
- Behind load balancer/proxy, `r.RemoteAddr` is the proxy IP
- Should check `X-Forwarded-For` header first

**Medium: OAuth State Has No Timestamp Check**
- State parameter never expires (deleted only on use)
- Intercepted state could be replayed indefinitely

**Low: Token Store Lock Contention**
- Single global `RWMutex` map for all users
- With thousands of concurrent users, lock contention will be severe
- Consider sharded map or Redis for production scale

---

### C. FRONTEND (`templates/rtm.html` — Confluence JS)

**High: 880 Lines of Inline JavaScript**
- All Confluence functions in single `<script>` block
- No modularization, no separation of concerns
- Should extract to `/static/js/confluence.js`

**High: 4 Global Variables with No Encapsulation**
```javascript
let confluenceData = null;
let confluenceSummary = null;
let selectedImageIndex = 0;
let confluenceOAuthConnected = false;
```
- Global namespace pollution
- No state machine, no validation of transitions

**High: Race Condition**
- If `summarizeConfluenceData()` is in flight when `clearConfluenceData()` runs, the summary callback will write to cleared/hidden UI elements
- Need `AbortController` to cancel in-flight requests on clear

**Medium: Inline CSS Everywhere**
- Every element has inline `style=` attributes (150+ char strings)
- Same button styles duplicated 4+ times
- Should use CSS classes

**Medium: HTML via String Concatenation + Inline `onclick`**
```javascript
statusDiv.innerHTML = '<a href="#" onclick="previewConfluenceData(); return false;" ...'
```
- Hard to maintain, test, and read
- Should use `addEventListener` and event delegation

**Medium: No Duplicate-Click Prevention**
- Fetch button disabled only after async call starts
- Multiple rapid clicks can trigger multiple fetches

**Low: `sessionStorage` Stores Confluence URLs**
- Could leak internal page IDs across navigation
- Should use more scoped mechanism

---

## Improvement Plan — 6 Phases

### Phase 1: Constants + Error Handling Foundation

**Goal**: Eliminate magic strings/numbers, establish single error pattern.

| Change | File | Risk |
|--------|------|------|
| Add API path constants, auth scheme constants, body limit constants | `confluence_validate.go` | Low |
| Add handler constants (rate limits, intervals, scopes, body limits) | `confluenceHandlers.go` | Low |
| Add CaaS constants (auth scheme, response limit, SSO env) | `caas_client.go` | Low |
| Create `checkAPIResponse()` helper — replaces 3 duplicated blocks | `confluence.go` | Low |

### Phase 2: Bug Fixes (Priority!)

**Goal**: Fix the 2 bugs and 1 ignored error.

| Change | File | Risk |
|--------|------|------|
| Parse error on 201 → fail immediately, don't retry | `caas_client.go` ~line 408 | Low |
| `getSSOToken()` → accept parent context, derive timeout | `caas_client.go` ~line 186 | Low |
| Check `ReadFrom()` error on response body | `caas_client.go` ~line 390 | Low |

### Phase 3: Break Up God Functions

**Goal**: Split massive functions into focused, testable helpers.

| Change | File | Risk |
|--------|------|------|
| Split `fetchImages()` → `fetchAttachmentMetadata()` + `deduplicateAttachments()` + `filterAndDownloadAttachments()` | `confluence.go` | Medium |
| Refactor `Fetch()` — return `*url.URL` from validate, move credential check first | `confluence.go`, `confluence_validate.go` | Medium |
| Split `buildRequest()` → `setBearerAuth()` + `setBasicAuth()` | `confluence.go` | Low |
| Fix `buildImageDownloadURL()` fall-through → if/else-if/else | `confluence.go` | Low |
| Split `Summarize()` → `buildCaaSRequest()` + `doWithRetry()` | `caas_client.go` | Medium |
| Rename variables: `dlLink`→`downloadLink`, `att`→`attachment`, etc. | `confluence.go` | Low |

### Phase 4: Infrastructure Improvements

**Goal**: Proper HTTP client, retries, externalize config.

| Change | File | Risk |
|--------|------|------|
| Configure `http.Transport` with connection pooling | `connector.go` | Low |
| Add `doHTTPWithRetry()` for transient failures (429, 5xx) | `confluence.go` | Medium |
| Externalize `ssojwt` environment to `CaaSConfig` | `caas_client.go`, config | Low |
| Move system prompt to embedded file (`//go:embed`) | `caas_client.go`, new `.md` file | Low |

### Phase 5: Handler Improvements

**Goal**: Clean up handlers, fix ignored errors, standardize responses.

| Change | File | Risk |
|--------|------|------|
| Extract `init()` goroutine to `StartConfluenceCleanup(ctx)` | `confluenceHandlers.go`, `main.go` | Low |
| Fix 3 silently ignored errors (lines 188, 263, 616) | `confluenceHandlers.go` | Low |
| Create `writeJSONError()` — standardize all error responses | `confluenceHandlers.go` | Low |
| Harden rate limiter key (check `X-Forwarded-For`) | `confluenceHandlers.go` | Low |

### Phase 6: Frontend Cleanup

**Goal**: Modular JS, encapsulated state, no race conditions.

| Change | File | Risk |
|--------|------|------|
| Extract Confluence functions to `/static/js/confluence.js` | `rtm.html`, new JS file | Low |
| Wrap globals in `ConfluenceModule` object | `confluence.js` | Low |
| Add `AbortController` to fix summarize/clear race | `confluence.js` | Low |
| Add `_fetchInFlight` guard for duplicate clicks | `confluence.js` | Low |
| Extract inline styles to CSS classes | `rtm.html` | Low |
| Replace `onclick` with `addEventListener` / event delegation | `rtm.html`, `confluence.js` | Low |

---

## Implementation Order

```
Phase 1 (Constants) → Phase 2 (Bug Fixes) → Phase 3 (God Functions) → Phase 5 (Handlers) → Phase 4 (Infrastructure) → Phase 6 (Frontend)
```

Bug fixes (Phase 2) are prioritized because:
- Parse-error retry bug wastes resources and delays error feedback to users
- Context override bug could cause SSO token fetch to outlive its parent HTTP request

---

## Verification After Each Phase

1. `go build ./...` — confirms compilation
2. `go vet ./...` — catches common mistakes
3. Manual test flow: OAuth login → fetch Confluence page → summarize → generate threat model
4. Verify `[AUDIT]` log entries still appear correctly
5. Test rate limiting (hit endpoint >10x/min, confirm 429)
6. Test image pipeline (page with images, verify magic byte validation)
7. Test error cases (bad URL, expired token, invalid page ID)
