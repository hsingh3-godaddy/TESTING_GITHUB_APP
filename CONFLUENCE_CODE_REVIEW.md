# Confluence Integration — Production Security Audit

**Date:** 2026-03-24
**Auditor:** Automated Security Review
**Scope:** `handlers/confluenceHandlers.go`, `connectors/confluence.go`, `connectors/confluence_validate.go`, `connectors/caas_client.go`, `templates/rtm.html`, `main.go` (Confluence routes)

---

## 1. EXECUTIVE SUMMARY

**Verdict:** ⚠️ CONDITIONAL — Production-ready with 2 medium issues to address

**Overall Score: 82/100**

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 4 |

**Estimated Fix Time:** 2-3 hours

---

## 2. WHAT'S BEEN HARDENED (Previously Fixed)

| Control | Implementation | Status |
|---------|---------------|--------|
| **OAuth tokens server-side only** | `confluenceTokenStore` in-memory map, keyed by Okta email. Token NEVER in browser cookie. | ✅ Secure |
| **No hardcoded session key** | Crypto-random 32-byte ephemeral fallback via `crypto/rand` | ✅ Secure |
| **CSRF protection** | Random 16-byte state parameter validated on OAuth callback | ✅ Secure |
| **Session cookie flags** | `HttpOnly`, `Secure` (TLS-conditional), `SameSite=Lax`, `MaxAge=300` | ✅ Secure |
| **No credential logging** | `fmt.Printf` token dump deleted. SSO token logs only `length=%d`. | ✅ Secure |
| **XSS prevention (frontend)** | `escapeHtml()` applied to all `innerHTML` injections | ✅ Secure |
| **XSS prevention (backend)** | 9-step sanitization pipeline strips dangerous tags, event handlers, comments | ✅ Secure |
| **SSRF protection** | HTTPS-only + `*.atlassian.net` domain allowlist + `/wiki/` path check | ✅ Secure |
| **Image polyglot prevention** | Magic byte verification (`validateImageMagicBytes`) called after every download | ✅ Secure |
| **Image type allowlist** | Only `image/png`, `image/jpeg`, `image/webp` accepted | ✅ Secure |
| **DoS prevention** | Body size limits (1MB URL, 50MB summarize, 5MB page, 10MB image), max 10 images | ✅ Secure |
| **Rate limiting** | Token-bucket per user on fetch/summarize endpoints (10 req/min, burst 5) | ✅ Secure |
| **Method restriction** | Login: GET-only. Fetch/Summarize: POST-only. | ✅ Secure |
| **Dead code removed** | Image proxy handler + route deleted. console.log statements removed. | ✅ Clean |

---

## 3. MEDIUM FINDINGS

### 🟡 M-1: Rate Limit Buckets Never Expire — Unbounded Memory Growth

**Location:** `handlers/confluenceHandlers.go:35`

**Issue:** `rateLimitBuckets` is a `map[string]*rateLimitEntry` that grows forever. Every unique user key (email or IP) adds an entry that is never removed. Over months in production, this map will consume increasing memory.

**Impact:** Memory leak. In a production environment with hundreds of users over time, the map accumulates entries for users who will never return.

**Fix:** Add a periodic cleanup goroutine:
```go
go func() {
    ticker := time.NewTicker(10 * time.Minute)
    for range ticker.C {
        rateLimitMu.Lock()
        now := time.Now()
        for key, entry := range rateLimitBuckets {
            if now.Sub(entry.lastCheck) > 10*time.Minute {
                delete(rateLimitBuckets, key)
            }
        }
        rateLimitMu.Unlock()
    }
}()
```

---

### 🟡 M-2: In-Memory Token Store Never Evicts Expired Tokens

**Location:** `handlers/confluenceHandlers.go:96`

**Issue:** `confluenceTokenStore` entries are never removed, even after tokens expire (1 hour). The `getConfluenceAuthFromSession` function checks expiry and returns an error, but the stale entry stays in the map forever.

**Impact:** Memory leak + expired tokens sitting in memory increase window for memory dump attacks.

**Fix:** Evict inline when detected expired + background cleanup:
```go
// Inline eviction in getConfluenceAuthFromSession:
if entry.Expiry > 0 && time.Now().Unix() > entry.Expiry-60 {
    confluenceTokenStoreMu.Lock()
    delete(confluenceTokenStore, userEmail)
    confluenceTokenStoreMu.Unlock()
    return nil, fmt.Errorf("confluence token expired")
}

// Background cleanup in init():
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    for range ticker.C {
        confluenceTokenStoreMu.Lock()
        now := time.Now().Unix()
        for email, entry := range confluenceTokenStore {
            if entry.Expiry > 0 && now > entry.Expiry {
                delete(confluenceTokenStore, email)
            }
        }
        confluenceTokenStoreMu.Unlock()
    }
}()
```

---

## 4. LOW FINDINGS

| ID | Issue | Location | Description |
|----|-------|----------|-------------|
| 🟢 L-1 | Token response body logged on error | `confluenceHandlers.go:266` | Non-200 token exchange logs `string(tokenBody)` which could contain error details from Atlassian. Low risk — only on failure paths. |
| 🟢 L-2 | `ssojwt` hardcoded to `dev` environment | `caas_client.go:189` | `--environment dev --cacheName dev` — should be configurable for production deployment. |
| 🟢 L-3 | No `url.PathEscape` on path segments | `confluence.go:285,369,592` | `pageID` and `attachmentID` inserted into URL without encoding. Currently safe (validated as numeric upstream), but lacks defense-in-depth. |
| 🟢 L-4 | `sessionStorage` URL not validated on restore | `rtm.html:210` | `pendingUrl` from `sessionStorage` used without regex validation. Low risk — `sessionStorage` is same-origin only. |

---

## 5. PRODUCTION CHECKLIST

- [x] OAuth tokens stored server-side only (never in cookies)
- [x] No hardcoded secrets (session key uses crypto-random fallback)
- [x] CSRF protection on OAuth flow (state parameter)
- [x] Session cookies: HttpOnly, Secure, SameSite=Lax
- [x] No credentials in logs
- [x] XSS prevention on all innerHTML injections + backend sanitization
- [x] SSRF protection: HTTPS + domain allowlist + path validation
- [x] Image polyglot prevention via magic byte verification
- [x] DoS prevention: body size limits, image count cap, rate limiting
- [x] Method restrictions on all endpoints
- [x] Dead code removed
- [x] Input validation on all user inputs
- [x] Error handling: generic to client, detailed server-side
- [x] Timeouts on all HTTP clients (10-30s per call, 120s CaaS)
- [x] Retry logic with exponential backoff (CaaS)
- [x] Response body size limits on all upstream reads
- [ ] **M-1:** Rate limit bucket eviction
- [ ] **M-2:** Expired token cleanup
- [ ] **L-2:** `ssojwt` environment configurable

---

## 6. SECURITY ARCHITECTURE

```
Browser                    GDSec360 Server                    External
  │                              │                               │
  │──── Okta JWT cookie ────────►│                               │
  │                              │                               │
  │  GET /auth/confluence/login  │                               │
  │  (Okta JWT validated)        │                               │
  │                              │── state+email in cookie ──►   │
  │  ◄── 302 to Atlassian ──────│   (100 bytes, 5 min TTL)      │
  │                              │                               │
  │  GET /auth/confluence/callback (from Atlassian)              │
  │                              │── validate state              │
  │                              │── exchange code ──────────►Atlassian
  │                              │◄── access_token (2290 B)      │
  │                              │── store in memory[email] ─►   │
  │                              │── delete cookie               │
  │  ◄── 302 to /ui/rtm ────────│                               │
  │                              │                               │
  │  POST /api/confluence/fetch  │                               │
  │  (Okta JWT validated)        │                               │
  │                              │── lookup token by email       │
  │                              │── fetch page+images ──────►Atlassian
  │                              │── sanitize + magic bytes      │
  │  ◄── JSON (content+base64) ──│                               │
  │                              │                               │
  │  POST /api/confluence/summarize                              │
  │  (Okta JWT validated)        │                               │
  │                              │── SSO JWT auth ───────────►CaaS
  │  ◄── JSON (summary) ────────│                               │
```

**Key security properties:**
- Access token never reaches the browser
- Every API call requires valid Okta JWT
- All Confluence URLs validated against SSRF allowlist
- All image data verified with magic bytes
- All user-facing content sanitized for XSS
- Rate limited per user identity
