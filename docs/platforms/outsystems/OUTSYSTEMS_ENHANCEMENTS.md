# OutSystems Security Scanner Enhancements

## Overview

This document describes the enhanced vulnerability detection capabilities added to the OutSystems analyzer to match industry-standard security scanning tools like Burp Suite.

## New Vulnerability Detections

### 1. Session Token in URL (Medium Severity)
**Description:** Detects session tokens, authentication codes, or state parameters in URL query strings.

**Why it matters:** URLs are logged, bookmarked, and can leak via Referer headers, exposing sensitive session data.

**Examples detected:**
- `session_code=`
- `session_state=`
- `access_token=`
- `auth_token=`
- `nonce=`
- `client_id=`
- `tab_id=`

**Recommendation:** Use HTTP cookies or POST body for session tokens.

---

### 2. Secrets/Credentials in JavaScript (Critical Severity)
**Description:** Identifies hardcoded secrets, API keys, tokens, and credentials in client-side JavaScript code.

**Why it matters:** Client-side code is accessible to anyone, making exposed secrets a critical security risk.

**Types detected:**
- API Keys
- Secret/Passwords
- Authentication Tokens
- Private Keys
- Client Secrets
- Access Keys
- AWS Secrets
- Database Passwords

**Recommendation:** Move all secrets to server-side configuration and environment variables.

---

### 3. Cookie Security Issues (Low-Medium Severity)

#### 3.1 Cookie without HttpOnly flag (Low)
**Description:** Cookies accessible via JavaScript, vulnerable to XSS attacks.

**Recommendation:** Set `HttpOnly` flag on session cookies.

#### 3.2 Cookie without Secure flag (Medium)
**Description:** Cookies that can be transmitted over HTTP.

**Recommendation:** Set `Secure` flag to ensure HTTPS-only transmission.

#### 3.3 Cookie without SameSite attribute (Low)
**Description:** Cookies vulnerable to CSRF attacks.

**Recommendation:** Set `SameSite=Strict` or `SameSite=Lax`.

---

### 4. Content Security Policy (CSP) Issues

#### 4.1 Missing CSP (Medium)
**Description:** No Content-Security-Policy header present.

**Recommendation:** Implement CSP to prevent XSS and injection attacks.

#### 4.2 Allows untrusted script execution (High)
**Description:** CSP contains `'unsafe-inline'` in `script-src` directive.

**Recommendation:** Remove `'unsafe-inline'` and use nonces or hashes.

#### 4.3 Allows untrusted style execution (Medium)
**Description:** CSP contains `'unsafe-inline'` in `style-src` directive.

**Recommendation:** Remove `'unsafe-inline'` from style directives.

#### 4.4 Allows unsafe-eval (High)
**Description:** CSP permits `'unsafe-eval'`, allowing dynamic code evaluation.

**Recommendation:** Remove `'unsafe-eval'` and refactor code.

#### 4.5 Allows form hijacking (Medium)
**Description:** Missing `form-action` directive in CSP.

**Recommendation:** Add `form-action` to restrict form submission targets.

---

### 5. Clickjacking Vulnerabilities (Medium Severity)
**Description:** Missing X-Frame-Options header or CSP frame-ancestors directive.

**Why it matters:** Page can be embedded in an iframe for clickjacking attacks.

**Recommendation:** Add `X-Frame-Options: DENY` or `SAMEORIGIN`, or use CSP `frame-ancestors` directive.

---

### 6. Information Disclosure

#### 6.1 Email addresses disclosed (Information)
**Description:** Email addresses found in page content or JavaScript.

**Recommendation:** Obscure emails or use contact forms.

#### 6.2 Private IP addresses disclosed (Low)
**Description:** Internal IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x) exposed.

**Recommendation:** Remove private IPs from client-side code.

#### 6.3 Detailed error messages revealed (Low)
**Description:** Stack traces or detailed error messages visible to users.

**Recommendation:** Show generic errors to users, log details server-side only.

---

### 7. Input returned in response - Reflected (High Severity)
**Description:** User input from URL parameters reflected in response without encoding.

**Why it matters:** Potential Cross-Site Scripting (XSS) vulnerability.

**Recommendation:** Properly encode/escape all user input using context-appropriate encoding.

---

### 8. Path-relative stylesheet import (Low Severity)
**Description:** Stylesheets imported using relative paths instead of absolute or root-relative URLs.

**Why it matters:** Can be exploited for content hijacking.

**Recommendation:** Use absolute or root-relative URLs (starting with `/`).

---

### 9. Cacheable HTTPS response (Low Severity)
**Description:** Sensitive HTTPS responses that may be cached by proxies or browsers.

**Why it matters:** Cached data might be accessed by unauthorized users.

**Recommendation:** Add `Cache-Control: no-cache, no-store, must-revalidate` headers for sensitive data.

---

### 10. Base64-encoded data in parameter (Information)
**Description:** Base64-encoded data found in URL parameters.

**Why it matters:** Base64 is encoding, not encryption - easily decoded.

**Recommendation:** Don't transmit sensitive data in URL parameters, even if Base64-encoded.

---

## Comparison with Burp Suite Report

The enhanced OutSystems analyzer now detects all major vulnerability types found in the provided Burp Suite report for OutSystems applications:

| Vulnerability Type | Burp Suite | Our Scanner | Severity |
|-------------------|------------|-------------|----------|
| Session token in URL | ✓ | ✓ | Medium |
| Secrets in JavaScript | ✓ | ✓ | Critical |
| Cookie without HttpOnly | ✓ | ✓ | Low |
| Cookie without Secure | ✓ | ✓ | Medium |
| Cookie without SameSite | - | ✓ | Low |
| CSP: unsafe-inline scripts | ✓ | ✓ | High |
| CSP: unsafe-inline styles | ✓ | ✓ | Medium |
| CSP: unsafe-eval | ✓ | ✓ | High |
| CSP: form hijacking | ✓ | ✓ | Medium |
| Clickjacking | ✓ | ✓ | Medium |
| Email disclosure | ✓ | ✓ | Information |
| Private IP disclosure | ✓ | ✓ | Low |
| Error messages | ✓ | ✓ | Low |
| Reflected input (XSS) | ✓ | ✓ | High |
| Path-relative stylesheets | ✓ | ✓ | Low |
| Cacheable HTTPS | ✓ | ✓ | Low |
| Base64 in parameters | ✓ | ✓ | Information |

## Usage

The enhancements are automatically applied when scanning OutSystems applications:

```python
from src.website_security_scanner.main import LowCodeSecurityScanner

scanner = LowCodeSecurityScanner()
results = scanner.scan_url("https://your-app.outsystems.app")

# All new vulnerability checks are automatically performed
```

## Testing

A comprehensive test suite is provided in `test_outsystems_enhancements.py`:

```bash
python3 test_outsystems_enhancements.py
```

This test suite validates all 17 new vulnerability detection methods.

## Implementation Details

### Detection Methods

All detection methods are implemented in the `OutSystemsAnalyzer` class:

- `_check_session_tokens_in_url()` - Regex pattern matching for session parameters
- `_check_secrets_in_javascript()` - Pattern matching for various secret types
- `_check_cookie_security()` - HTTP header analysis for cookie flags
- `_check_csp_policy()` - CSP header parsing and directive analysis
- `_check_clickjacking()` - X-Frame-Options and CSP frame-ancestors check
- `_check_information_disclosure()` - Regex matching for emails, IPs, and errors
- `_check_reflected_input()` - Parameter value reflection analysis
- `_check_path_relative_stylesheets()` - HTML link element analysis
- `_check_cacheable_https()` - Cache-Control header analysis
- `_check_base64_data()` - Base64 pattern matching and decoding

### False Positive Reduction

The implementation includes several mechanisms to reduce false positives:

1. **Context-aware detection**: Checks are only performed when relevant (e.g., HTTPS caching only for HTTPS URLs)
2. **Pattern validation**: Base64 is validated by attempting to decode
3. **Blacklisting common false positives**: Skips placeholder values like "password", "xxxx", etc.
4. **Length thresholds**: Requires minimum lengths for secrets to avoid detecting test data

## Future Enhancements

Potential areas for further development:

1. **Active testing**: Probe for vulnerabilities beyond passive analysis
2. **JavaScript execution**: Use headless browser for dynamic analysis
3. **API endpoint testing**: Automatically test discovered API endpoints
4. **Authentication bypass**: Test for authentication/authorization flaws
5. **SQL injection**: Test input points for SQL injection
6. **Command injection**: Test for OS command injection vulnerabilities

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
