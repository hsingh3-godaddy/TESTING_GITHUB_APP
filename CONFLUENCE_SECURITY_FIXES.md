# Security Review & Fix Plan — Confluence Integration

## Context
A comprehensive security audit of the Confluence OAuth 2.0 (3LO) integration across 8 files. The review identified **4 Critical**, **5 High**, **4 Medium**, and **2 Low** severity issues. This plan addresses every finding with specific fixes.

---

## Findings & Fixes

### CRITICAL-1: Hardcoded Session Signing Key
**File:** `handlers/confluenceHandlers.go:45`
**Risk:** Anyone who reads the source code (or the Git repo) can forge arbitrary session cookies, impersonate any user, and steal OAuth tokens.
```go
// VULNERABLE
confluenceSessionStore = sessions.NewFilesystemStore(sessionDir, []byte("3107638e-f80f-11ef-bd97-56fdc237bf29"))
```
**Fix:** Load the key from an environment variable or AWS Secrets Manager. Add to `ConfluenceConfig`:
```go
SessionSigningKey string // from env CONFLUENCE_SESSION_KEY
```
In `init()`:
```go
key := []byte(config.Config.ConfluenceConfig.SessionSigningKey)
if len(key) == 0 {
    key = make([]byte, 32)
    rand.Read(key) // ephemeral fallback for local dev
}
confluenceSessionStore = sessions.NewFilesystemStore(sessionDir, key)
```

---

### CRITICAL-2: Stored XSS via `innerHTML` — Confluence Page Title
**File:** `templates/rtm.html:323, 401, 500`
**Risk:** Confluence page titles are attacker-controlled. A title like `<img src=x onerror=alert(document.cookie)>` executes JavaScript in every user's browser, stealing session cookies.
```js
// VULNERABLE (line 323)
statusDiv.innerHTML = '<i class="fas fa-check-circle"></i> <strong>' + confluenceData.title + '</strong>'...
```
**Fix:** Create an `escapeHtml()` utility and use it on all dynamic values before injection:
```js
function escapeHtml(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}
```
Apply to: `confluenceData.title` (lines 323, 401, 500), `error.message` (lines 346, 418), `img.filename` (line 526), `img.content_type` (lines 525, 629).

---

### CRITICAL-3: XSS via Image Proxy — No Content-Type Validation
**File:** `handlers/confluenceHandlers.go:587-588`
**Risk:** The image proxy blindly forwards whatever `Content-Type` Confluence returns. If an attacker uploads an HTML file as an attachment, the proxy serves it as `text/html`, executing scripts in the app's origin.
```go
// VULNERABLE
if ct := resp.Header.Get("Content-Type"); ct != "" {
    w.Header().Set("Content-Type", ct)
}
```
**Fix:** Only allow known image MIME types. Reject everything else:
```go
allowedCT := map[string]bool{"image/png": true, "image/jpeg": true, "image/webp": true, "image/gif": true}
ct := resp.Header.Get("Content-Type")
baseCT := strings.Split(ct, ";")[0]
if !allowedCT[strings.TrimSpace(strings.ToLower(baseCT))] {
    http.Error(w, "Disallowed content type", http.StatusForbidden)
    return
}
w.Header().Set("Content-Type", ct)
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("Content-Security-Policy", "default-src 'none'")
```

---

### CRITICAL-4: `validateImageMagicBytes` Defined But Never Called
**File:** `connectors/confluence_validate.go:245` (defined), `connectors/confluence.go` (not called)
**Risk:** The entire magic-byte verification pipeline is dead code. Polyglot attacks (HTML disguised as PNG) pass through unchecked. The image proxy then serves them as HTML (CRITICAL-3).
**Fix:** Call it in `fetchImages()` after `doDownload()`:
```go
imgData, err := c.doDownload(ctx, resolvedURL)
if err != nil { ... }
if !validateImageMagicBytes(imgData, mediaType) {
    filtered++
    logger.Warnf("confluence: skipping %q (magic bytes don't match declared type %s)", att.Title, mediaType)
    continue
}
```

---

### HIGH-1: Session Cookie Missing Security Flags
**File:** `handlers/confluenceHandlers.go:45-46`
**Risk:** Without `Secure`, `HttpOnly`, `SameSite` flags: cookies are sent over HTTP (credential theft on network), accessible via JavaScript (XSS exploitation), and sent in cross-site requests (CSRF).
**Fix:** Add after creating the store:
```go
confluenceSessionStore.Options = &sessions.Options{
    Path:     "/",
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
    MaxAge:   3600, // 1 hour
}
```

---

### HIGH-2: OAuth Login Endpoint Not Method-Restricted
**File:** `handlers/confluenceHandlers.go:51`
**Risk:** GET requests to `/auth/confluence/login` redirect the user to Atlassian. An attacker can trigger this via `<img src="/auth/confluence/login">` on any page (CSRF initiation attack).
**Fix:** Restrict to POST only:
```go
func ConfluenceAuthLoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    ...
```
Update the frontend `redirectToConfluenceOAuth()` to send a POST (via a form submit).

---

### HIGH-3: Credential/Token Logging
**File:** `connectors/caas_client.go:203, 355`
**Risk:** SSO tokens are partially logged. If logs are compromised, attacker gets valid tokens.
```go
// VULNERABLE (line 203)
logger.Infof("[CaaS Auth] SSO token obtained, length=%d, preview=%s...", len(token), token[:min(40, len(token))])
// VULNERABLE (line 355)
logger.Infof("[CaaS] Auth header: Authorization: sso-jwt %s...%s", token[:min(20, len(token))], token[max(0, len(token)-10):])
```
**Fix:** Remove token content from logs. Only log length/presence:
```go
logger.Infof("[CaaS Auth] SSO token obtained, length=%d", len(token))
// Remove line 355 entirely
```

---

### HIGH-4: Debug Logging Leaks OAuth Tokens and Full URLs
**File:** `connectors/confluence.go:162, 257, 269, 395, 429, 588`
**Risk:** OAuth Bearer tokens and full request URLs (which may contain tokens in query strings) are logged at INFO level.
**Fix:** Change all `[DEBUG]` log lines to use `logger.Debugf` instead of `logger.Infof`, and remove token content from logs. Specifically:
- Line 257: Remove `auth.CloudID` from log (it reveals user identity)
- Line 269: Don't log `URL=%s` for basic auth (may contain credentials in URL)
- Remove or redact any log line that contains an `Authorization` header value

---

### HIGH-5: Image Proxy Passes Through Confluence Error Responses
**File:** `handlers/confluenceHandlers.go:582`
**Risk:** If Confluence returns an error (e.g., 403 with HTML body), the proxy forwards the raw status code. The `fmt.Sprintf` includes the status code in the error response, which is fine, but the raw Confluence error body is not sanitized and could contain XSS.
```go
http.Error(w, fmt.Sprintf("Confluence returned status %d", resp.StatusCode), resp.StatusCode)
```
**Fix:** Already mostly safe since `http.Error` sets `text/plain` content type. But using `resp.StatusCode` directly as the HTTP status could forward unexpected codes. Use a fixed gateway error:
```go
http.Error(w, fmt.Sprintf("Upstream returned status %d", resp.StatusCode), http.StatusBadGateway)
```

---

### MEDIUM-1: Session MaxLength(0) — Unlimited Session Size
**File:** `handlers/confluenceHandlers.go:46`
**Risk:** No limit on session data size allows potential DoS by stuffing large values into the session.
**Fix:** Set a reasonable limit:
```go
confluenceSessionStore.MaxLength(8192) // 8 KB is plenty for OAuth tokens
```

---

### MEDIUM-2: No Rate Limiting on OAuth/Fetch/Summarize Endpoints
**File:** `main.go:310-320`
**Risk:** An attacker can brute-force OAuth flows, flood the Confluence API, or abuse the AI summarization endpoint (which is expensive).
**Fix:** Add rate limiting middleware (at minimum log and document as a known gap to address via API gateway or middleware). This is an architectural issue — recommend documenting for next sprint.

---

### MEDIUM-3: `sessionStorage` Stores Pending URL — XSS Amplification
**File:** `templates/rtm.html:132-142`
**Risk:** If any XSS exists (see CRITICAL-2), an attacker can inject a malicious URL into `sessionStorage` that auto-fetches on page load.
**Fix:** Validate the stored URL before using it:
```js
if (pendingUrl && /^https:\/\/[a-z0-9-]+\.atlassian\.net\/wiki\//.test(pendingUrl)) {
    document.getElementById('confluenceUrl').value = pendingUrl;
    ...
```

---

### MEDIUM-4: Missing `X-Content-Type-Options: nosniff` on All Responses
**Risk:** Browsers may MIME-sniff responses and interpret non-HTML as HTML.
**Fix:** Add `X-Content-Type-Options: nosniff` header in the image proxy (covered in CRITICAL-3 fix) and ideally as a global middleware.

---

### LOW-1: Session Files in `/tmp` Directory
**File:** `handlers/confluenceHandlers.go:41`
**Risk:** Other processes on the same machine can read session files containing OAuth tokens.
**Fix:** Use a more restrictive path (e.g., within the app's data directory) with 0700 permissions. Already has 0700, so this is low risk. Document as known limitation.

---

### LOW-2: `buildImageDownloadURL` Doesn't URL-Encode Path Segments
**File:** `connectors/confluence.go:587`
**Risk:** Page IDs and attachment IDs are validated as numeric upstream, so this is currently safe. But if validation changes, path traversal could occur.
**Fix:** Use `url.PathEscape()` for defense in depth:
```go
u := fmt.Sprintf("%s/wiki/rest/api/content/%s/child/attachment/%s/download",
    baseURL, url.PathEscape(pageID), url.PathEscape(attachmentID))
```

---

## Implementation Order

1. **CRITICAL-1** — Hardcoded session key -> env/secrets (`config/config.go`, `handlers/confluenceHandlers.go`)
2. **CRITICAL-2** — XSS escaping in `templates/rtm.html` (add `escapeHtml()`, apply everywhere)
3. **CRITICAL-3** — Image proxy Content-Type allowlist + `nosniff` header (`handlers/confluenceHandlers.go`)
4. **CRITICAL-4** — Wire up `validateImageMagicBytes` call (`connectors/confluence.go`)
5. **HIGH-1** — Session cookie flags (`handlers/confluenceHandlers.go`)
6. **HIGH-2** — Method restrict OAuth login to POST (`handlers/confluenceHandlers.go`, `templates/rtm.html`)
7. **HIGH-3 + HIGH-4** — Remove token/credential logging (`caas_client.go`, `confluence.go`)
8. **HIGH-5** — Fixed status code on proxy error (`handlers/confluenceHandlers.go`)
9. **MEDIUM-1** — Session MaxLength (`handlers/confluenceHandlers.go`)
10. **MEDIUM-3** — URL validation on sessionStorage (`templates/rtm.html`)
11. **MEDIUM-4** — nosniff header (covered by CRITICAL-3)
12. **LOW-1, LOW-2** — Defensive improvements
13. **MEDIUM-2** — Rate limiting (document as known gap)

## Files to Modify

| File | Changes |
|------|---------|
| `config/config.go` | Add `SessionSigningKey` field to `ConfluenceConfig`, load from env |
| `handlers/confluenceHandlers.go` | Session key from config, cookie flags, method restriction, Content-Type allowlist, status code fix, MaxLength |
| `templates/rtm.html` | Add `escapeHtml()`, apply to all `innerHTML` injections, validate sessionStorage URL, update OAuth redirect to POST |
| `connectors/confluence.go` | Call `validateImageMagicBytes`, URL-encode path segments, downgrade debug logs |
| `connectors/caas_client.go` | Remove token content from log lines |

## Verification

1. **XSS test:** Create a Confluence page with title `<img src=x onerror=alert(1)>` — verify it displays as text, not executing
2. **Session cookie:** Inspect cookie in browser DevTools -> verify `HttpOnly`, `Secure`, `SameSite=Lax` flags present
3. **Image proxy:** Request `/api/confluence/image-proxy?url=...` with a URL that returns `text/html` — verify 403 Forbidden
4. **Magic bytes:** Upload a `.html` file renamed to `.png` as a Confluence attachment — verify it's filtered out
5. **Credential logging:** Search logs for token content after a fetch — verify none present
6. **OAuth POST:** Verify `/auth/confluence/login` returns 405 on GET
7. **Session key:** Verify the app starts without the hardcoded key, reads from env
