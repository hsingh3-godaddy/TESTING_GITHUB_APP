# Security Review: Confluence OAuth 2.0 (3LO) Integration

**Reviewer:** Claude Security Audit
**Date:** 2026-03-20
**Branch:** `rtm-confluence-connector`
**Scope:** All modified files — connectors, handlers, config, templates

---

## 1. EXECUTIVE SUMMARY

**Verdict:** ⚠️ CONDITIONAL — Deployable after addressing Critical and High findings

**Overall Score: 72/100**

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 5 |
| 🟡 Medium | 6 |
| 🟢 Low | 4 |

**Estimated Fix Time:** 4-6 hours

---

## 2. 🔴 CRITICAL FINDINGS (Deployment Blockers)

### CRIT-01: Hardcoded Session Key Fallback

**File:** `handlers/confluenceHandlers.go:87`

```go
sessionKey := config.Config.OktaConfig.SessionKey
if sessionKey == "" {
    sessionKey = "3107638e-f80f-11ef-bd97-56fdc237bf29" // dev fallback only
}
confluenceSessionStore = sessions.NewCookieStore([]byte(sessionKey))
```

**Vulnerability:** If `OktaConfig.SessionKey` is ever empty in production (misconfiguration, secret rotation failure), the application silently falls back to a publicly-known, hardcoded key. Any attacker who reads this source code can forge session cookies, including injecting arbitrary `confluence_access_token` and `confluence_cloud_id` values.

**Attack scenario:**
1. Attacker reads the hardcoded UUID from source (it's committed to git)
2. Attacker crafts a signed cookie using the known key
3. Attacker injects a forged `confluence_access_token` into the session
4. All Confluence API calls from the image proxy and fetch handlers use the attacker-controlled token

**Fix:**
```go
func init() {
    sessionKey := config.Config.OktaConfig.SessionKey
    if sessionKey == "" {
        logger.Fatalf("FATAL: OktaConfig.SessionKey is not set - refusing to start with insecure default")
    }
    if len(sessionKey) < 32 {
        logger.Fatalf("FATAL: OktaConfig.SessionKey is too short (minimum 32 bytes)")
    }
    confluenceSessionStore = sessions.NewCookieStore([]byte(sessionKey))
    // ...
}
```

**Impact:** Complete session forgery -> unauthorized access to any user's Confluence data.

---

### CRIT-02: OAuth Access Token Stored in Cookie (Client-Side) Without Encryption

**File:** `handlers/confluenceHandlers.go:272`

```go
session.Values["confluence_access_token"] = tokenResult.AccessToken
```

The `confluenceSessionStore` uses `sessions.CookieStore`, which means the entire session (including the raw Atlassian OAuth access token) is stored in the browser cookie. Even though cookies are HMAC-signed and `HttpOnly`, they are **not encrypted**.

Gorilla `CookieStore` does NOT encrypt by default -- it only signs. You must pass an encryption key as the second argument.

**Vulnerability:** The access token is visible in plaintext to:
- Anyone with physical/remote access to the browser
- Browser extensions with cookie access
- Network proxies if TLS is terminated early (corporate MITM proxies)
- Any XSS in the application (though HttpOnly mitigates document.cookie access)

**Fix:**
```go
func init() {
    sessionKey := config.Config.OktaConfig.SessionKey
    // ... validation ...

    // Use separate auth key (32 bytes) and encryption key (32 bytes for AES-256)
    authKey := []byte(sessionKey)[:32]
    encKey := deriveEncryptionKey(sessionKey) // HKDF or similar derivation
    confluenceSessionStore = sessions.NewCookieStore(authKey, encKey)
}
```

Alternatively, switch to a server-side session store (Redis, DB-backed) so the token never leaves the server.

**Impact:** Exposure of OAuth access tokens -> unauthorized Confluence API access.

---

### CRIT-03: Rate Limiter Memory Leak (Unbounded Growth)

**File:** `handlers/confluenceHandlers.go:35`

```go
var rateLimitBuckets = make(map[string]*rateLimitEntry)
```

The `rateLimitBuckets` map grows without bound. Every unique `userKey` (email or IP address) creates a permanent entry. There is no eviction, TTL, or garbage collection.

**Attack scenario:**
1. Attacker sends requests with spoofed `X-Forwarded-For` headers or different JWT-less IPs
2. Each request creates a new rate limit entry
3. Over hours/days, the map consumes all available memory
4. Application OOMs -> denial of service for all users

**Fix:** Add periodic cleanup:
```go
func init() {
    // Evict stale entries every 5 minutes
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        for range ticker.C {
            rateLimitMu.Lock()
            cutoff := time.Now().Add(-10 * time.Minute)
            for key, entry := range rateLimitBuckets {
                if entry.lastCheck.Before(cutoff) {
                    delete(rateLimitBuckets, key)
                }
            }
            rateLimitMu.Unlock()
        }
    }()
}
```

**Impact:** Denial of service via memory exhaustion.

---

## 3. 🟠 HIGH PRIORITY ISSUES (Fix within 48 hours)

### HIGH-01: Confluence OAuth Callback Unprotected by Okta Auth

**File:** `main.go:314`

```go
http.Handle("/auth/confluence/callback", wrapHandlerFuncWithTraceAndLogging(handlers.ConfluenceAuthCallbackHandler))
```

The callback endpoint has no Okta authentication middleware. The comment explains this is intentional because "Atlassian redirect won't carry the JWT." However, the CSRF protection relies solely on the OAuth state parameter stored in a cookie session.

**Risk:** If the cookie session store is compromised (CRIT-01), an attacker can:
1. Set a forged `oauth_state` in a cookie
2. Call `/auth/confluence/callback?code=ATTACKER_CODE&state=KNOWN_STATE`
3. Inject their own Atlassian access token into the victim's session

**Mitigation:** This is partially mitigated by the state parameter check -- but becomes a complete bypass if CRIT-01 is not fixed. Fix CRIT-01 first, then this becomes acceptable risk.

---

### HIGH-02: CloudID Not Validated Against Format or Allowlist

**File:** `connectors/confluence.go:120`

```go
return fmt.Sprintf("https://api.atlassian.com/ex/confluence/%s", auth.CloudID)
```

The `CloudID` comes from the user's session. If the session is compromised, an attacker could inject a path-traversal payload (e.g., `../../admin`) or access data from a different Atlassian organization.

**Fix:** Validate CloudID format (UUID only):
```go
var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func resolveBaseURL(ctx context.Context, directBaseURL string) string {
    if auth, ok := ConfluenceAuthFromContext(ctx); ok && auth.CloudID != "" {
        if !uuidRegex.MatchString(auth.CloudID) {
            logger.Errorf("confluence: invalid CloudID format: %s", auth.CloudID)
            return directBaseURL
        }
        return fmt.Sprintf("https://api.atlassian.com/ex/confluence/%s", auth.CloudID)
    }
    return directBaseURL
}
```

---

### HIGH-03: Image Proxy SSRF -- Incomplete Origin Validation

**File:** `handlers/confluenceHandlers.go:565-575`

```go
secFetchSite := r.Header.Get("Sec-Fetch-Site")
referer := r.Header.Get("Referer")
if secFetchSite != "" && secFetchSite != "same-origin" && secFetchSite != "same-site" {
    http.Error(w, "Cross-origin requests not allowed", http.StatusForbidden)
    return
}
if secFetchSite == "" && referer == "" {
    http.Error(w, "Missing origin headers", http.StatusForbidden)
    return
}
```

The `Sec-Fetch-Site` header is only sent by modern browsers. The fallback checks only that `referer != ""`, which is trivially bypassable (any HTTP client can set `Referer: anything`).

An attacker can bypass this by simply setting `Referer: https://your-app.com/` in their request, turning the image proxy into an authenticated SSRF gateway (limited to atlassian.net domains).

**Fix:** Require a custom header that triggers CORS preflight:
```go
if r.Header.Get("X-Requested-With") != "XMLHttpRequest" && secFetchSite == "" {
    http.Error(w, "Missing security headers", http.StatusForbidden)
    return
}
```

---

### HIGH-04: Stored XSS via Unsanitized Markdown -> HTML

**File:** `handlers/rtmHanlders.go:360`

```go
html := blackfriday.Run([]byte(markdown))
// ...
w.Write(html) // rendered from blackfriday
```

The `blackfriday` library renders markdown to HTML but does NOT sanitize the output. If an attacker can inject malicious markdown into a threat model result (e.g., via compromised AI output or direct DB modification), they can achieve stored XSS:

```markdown
[Click me](javascript:alert(document.cookie))
<img src=x onerror=alert(1)>
```

**Fix:** Pass blackfriday output through `bluemonday`:
```go
import "github.com/microcosm-cc/bluemonday"

unsafeHTML := blackfriday.Run([]byte(markdown))
p := bluemonday.UGCPolicy()
safeHTML := p.SanitizeBytes(unsafeHTML)
w.Write(safeHTML)
```

---

### HIGH-05: Content-Disposition Header Injection

**File:** `handlers/rtmHanlders.go:1339`

```go
w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
```

The `filename` is derived from `threatmodelname` in the database. While there's some sanitization (replacing `/` and `\`), it doesn't handle:
- Newline characters (`\r\n`) -> HTTP header injection
- Double quotes -> break out of the filename parameter

**Fix:**
```go
safeName := strings.Map(func(r rune) rune {
    if r < 32 || r == '"' || r == '\\' || r == '/' || r > 126 {
        return '-'
    }
    return r
}, sanitizedName)
w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeName))
```

---

## 4. 🟡 MEDIUM / 🟢 LOW PRIORITY

| ID | Issue | Category | File:Line | Effort | Priority |
|----|-------|----------|-----------|--------|----------|
| MED-01 | `Secure` cookie flag tied to `TLSConfig.Enabled` -- if TLS terminates at LB (common in ECS/EKS), cookies won't be marked secure | Security Misc. | `confluenceHandlers.go:92` | 5 min | 🟡 Medium |
| MED-02 | `exec.CommandContext(ctx, "ssojwt", ...)` -- ensure `ssojwt` binary is in a safe, non-user-writable PATH location | Command Injection | `caas_client.go:189` | 15 min | 🟡 Medium |
| MED-03 | `io.Copy(w, ...)` error silently discarded in image proxy response streaming | Error Handling | `confluenceHandlers.go:641` | 2 min | 🟡 Medium |
| MED-04 | OAuth token exchange logs full response body on error (`string(tokenBody)`) which may contain sensitive data | Data Exposure | `confluenceHandlers.go:232` | 5 min | 🟡 Medium |
| MED-05 | No `context.WithTimeout` on Confluence API requests -- relies solely on `http.Client.Timeout` (30s) | Availability | `confluence.go:295` | 10 min | 🟡 Medium |
| MED-06 | `pdfFilename` inserted into JS string literal without escaping -- XSS if filename contains quotes | XSS | `rtmHanlders.go:783` | 5 min | 🟡 Medium |
| LOW-01 | Double-spaced Go source in `confluence.go` (blank line between every line) -- code quality issue | Code Quality | `confluence.go` | 5 min | 🟢 Low |
| LOW-02 | `fetchConfluenceCloudID` always uses first resource -- should validate it's a Confluence site, not Jira | Logic | `confluenceHandlers.go:361` | 10 min | 🟢 Low |
| LOW-03 | `SameSite: LaxMode` -- consider `StrictMode` for Confluence session (same-origin API calls only) | Hardening | `confluenceHandlers.go:93` | 2 min | 🟢 Low |
| LOW-04 | Frontend `renderMarkdown()` uses regex-based rendering instead of a proper parser | Code Quality | `rtm.html:124` | N/A | 🟢 Low |

---

## 5. SECURITY ARCHITECTURE REVIEW

### What's Done Well

1. **SSRF Protection:** URL validation with HTTPS-only, domain allowlist (`.atlassian.net`, `api.atlassian.com`), and path prefix checks. This is solid.

2. **Image Validation Pipeline:** Magic byte verification against declared MIME type prevents polyglot attacks. Min/max size filtering removes tracking pixels and DoS payloads. Well-designed defense in depth.

3. **OAuth State Parameter:** CSRF protection via cryptographically random state parameter (16 bytes from `crypto/rand`), verified on callback. Standard best practice.

4. **Content Sanitization:** The 9-step pipeline in `sanitizeStorageFormat()` is thorough -- strips scripts, event handlers, HTML comments, self-closing tags, and converts to plain text.

5. **Rate Limiting:** Token bucket per-user rate limiting on all Confluence endpoints (fetch, summarize, image proxy). Good pattern (but needs eviction -- see CRIT-03).

6. **Request Body Limits:** `http.MaxBytesReader` on fetch (1 MB) and summarize (50 MB). `io.LimitReader` on all response bodies. Prevents DoS via large payloads.

7. **Audit Logging:** `[AUDIT]` prefixed log entries for all security-relevant operations with user attribution.

8. **XSS Prevention in Frontend:** `escapeHtml()` applied before innerHTML operations. Uses DOM-based escaping (`createTextNode` + `innerHTML` extraction), which is correct.

### What Needs Improvement

1. **Session Security:** Cookie-based session store with HMAC-only (no encryption) and a hardcoded fallback key is the weakest link.

2. **Token Lifecycle:** No refresh token handling -- users must fully re-authenticate on expiry. The 1-hour window is hard-limited.

3. **Missing Request ID Correlation:** Confluence-specific log entries don't consistently include trace/request IDs from the TraceMiddleware.

---

## 6. PRODUCTION CHECKLIST

- [ ] **CRIT-01** -- Remove hardcoded session key fallback, fail-closed on missing key
- [ ] **CRIT-02** -- Add encryption key to CookieStore or switch to server-side sessions
- [ ] **CRIT-03** -- Add rate limiter eviction / TTL cleanup goroutine
- [ ] **HIGH-01** -- Verify CSRF protection is sufficient after CRIT-01 fix
- [ ] **HIGH-02** -- Validate CloudID format (UUID regex)
- [ ] **HIGH-03** -- Strengthen image proxy origin validation
- [ ] **HIGH-04** -- Add HTML sanitizer (bluemonday) after blackfriday rendering
- [ ] **HIGH-05** -- Sanitize Content-Disposition filename for header injection
- [ ] **MED-01** -- Set `Secure: true` unconditionally for production (TLS at LB)
- [ ] Confluence OAuth `client_secret` is in AWS Secrets Manager (not env vars in prod)
- [ ] OAuth scopes are minimal: read-only page, attachment, content-details
- [ ] No secrets in logs (verified: auth headers are not logged)
- [ ] Error responses don't leak internal details to clients
- [ ] All Confluence endpoints behind `OktaJWTWithRBACMiddleware` (except callback -- by design)

---

## 7. RECOMMENDED NEXT STEPS

### Immediate (Pre-Deployment)
1. Fix CRIT-01, CRIT-02, CRIT-03 -- these are deployment blockers
2. Fix HIGH-04 (stored XSS) -- affects existing functionality too
3. Add `bluemonday` dependency: `go get github.com/microcosm-cc/bluemonday`

### Post-Deployment Monitoring
1. Monitor `rateLimitBuckets` map size via metrics/health endpoint
2. Alert on `[CaaS Auth] ssojwt failed` -- indicates service account issues
3. Monitor OAuth token exchange failure rates
4. Set up alerting for `confluence: authentication failed` log patterns

### Technical Debt
1. Consider migrating from `CookieStore` to `RedisStore` for session management
2. Add integration tests for the OAuth flow with mock Atlassian endpoints
3. Add CSRF tokens to the image proxy endpoint instead of relying on browser headers
4. Consider adding Confluence webhook subscriptions for real-time page update notifications