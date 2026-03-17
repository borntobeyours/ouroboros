# TASK: Polish Ouroboros to find 80+ valid findings on OWASP Juice Shop

## Current State
- Finding 10 vulns per scan (5 per loop, 2 loops)
- AI-based scanning returns too few results
- Only surface-level detection
- Active exploitation works but limited scope

## Target
Find **80+ unique, valid findings** from OWASP Juice Shop (http://localhost:3000)
Juice Shop has 100+ known challenges/vulnerabilities.

## Root Causes to Fix

### 1. Need Technique-Specific Active Probers (NOT just AI analysis)
Create dedicated probers that actually send HTTP requests and test each endpoint:

**a) SQLi Prober** (`internal/red/probers/sqli.go`)
- Test EVERY parameter on EVERY endpoint with SQLi payloads
- Error-based, blind boolean, time-based, UNION-based
- Target: /rest/products/search?q=, /rest/user/login (POST JSON), /api/* endpoints
- Juice Shop known SQLi: login bypass (`' OR 1=1--` as email), search endpoint

**b) XSS Prober** (`internal/red/probers/xss.go`)
- Test every input field, search param, URL param
- Reflected, stored (via API), DOM-based detection
- Juice Shop known: search reflected XSS, API stored XSS, DOM XSS via URL fragment

**c) IDOR Prober** (`internal/red/probers/idor.go`)
- Enumerate IDs on all /api/* and /rest/* endpoints
- Test /rest/basket/{1-10}, /api/Users/{1-10}, /rest/order-history/{emails}
- Access control: test endpoints with and without auth token

**d) Auth/Access Control Prober** (`internal/red/probers/auth.go`)
- Login with default creds (admin@juice-sh.op with SQLi bypass)
- Test admin endpoints without auth
- Test role escalation (user accessing admin routes)
- JWT token manipulation (none algorithm, weak secret)
- Password reset flow abuse
- Registration with admin role

**e) Info Leak Prober** (`internal/red/probers/infoleaks.go`)
- Check 100+ sensitive paths (/ftp/*, /encryptionkeys/*, /support/logs, etc.)
- Check ALL /api/* for data exposure without auth
- Error message analysis
- Source code exposure
- Swagger/API docs exposure
- Metrics/monitoring endpoint exposure

**f) Injection Prober** (`internal/red/probers/injection.go`)
- Command injection on all POST endpoints
- NoSQL injection on login and API endpoints
- XML/XXE injection
- Template injection (SSTI)
- Log injection

**g) Security Headers Prober** (`internal/red/probers/headers.go`)
- Check EVERY response for missing security headers
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
- Cookie flags (HttpOnly, Secure, SameSite)
- CORS misconfiguration

**h) File/Upload Prober** (`internal/red/probers/fileupload.go`)
- Test file upload endpoints for type bypass
- Path traversal in file names
- Unrestricted file upload

**i) SSRF Prober** (`internal/red/probers/ssrf.go`)
- Test /redirect endpoint
- Test URL parameters on all endpoints
- Internal service access

**j) Crypto/Token Prober** (`internal/red/probers/crypto.go`)
- JWT analysis (weak algorithm, none, key brute force)
- Session token predictability
- Weak password hashing detection

### 2. Authenticated Scanning
- First, LOGIN to Juice Shop (SQLi bypass: `' OR 1=1--`)
- Scan BOTH unauthenticated AND authenticated
- Test access control by comparing responses
- Use auth token for endpoints that require it

### 3. Better Endpoint Discovery
- Parse main.js THOROUGHLY for ALL routes (Juice Shop has 50+ API endpoints)
- Look for Angular route definitions
- Enumerate /api/{Model} for all Sequelize models
- Check /api-docs, /swagger.json if available
- Test common Juice Shop paths: /b2b/v2/orders, /file-upload, /profile, /dataerasure, etc.

### 4. Restructured Scanning Flow
Instead of asking AI to find vulns, do:
1. Crawl + discover endpoints (existing, enhance)
2. Run ALL technique-specific probers against ALL endpoints
3. Each prober generates findings independently
4. AI analyzes ambiguous results for confirmation
5. Deduplicate by (endpoint + technique + CWE) signature

### 5. Juice Shop Specific Paths to Test
```
/rest/user/login (POST - SQLi)
/rest/user/change-password (GET - password change without auth)
/rest/user/reset-password (POST)
/rest/user/whoami
/rest/user/authentication-details
/rest/user/erasure-request
/rest/products/{id}/reviews (PUT - forged reviews)
/rest/products/search?q= (SQLi + XSS)
/rest/saveLoginIp
/rest/deluxe-membership
/rest/wallet/balance
/rest/order-history
/rest/track-order/{id}
/rest/basket/{id} (IDOR)
/rest/admin/application-version
/rest/admin/application-configuration
/rest/repeat-notification
/rest/chatbot/respond
/rest/chatbot/status
/rest/captcha (answer exposed)
/rest/image-captcha
/rest/memories (POST - file upload)
/rest/continue-code
/rest/continue-code-findIt
/rest/country-mapping
/api/Users (GET - list all users without auth)
/api/Users/{id} (IDOR)
/api/Products (list products)
/api/Products/{id} (IDOR)
/api/Feedbacks (POST - feedback without auth)
/api/Feedbacks/{id} (DELETE - delete others' feedback)
/api/Complaints (POST)
/api/Recycles
/api/SecurityQuestions
/api/SecurityAnswers
/api/Cards
/api/Deliverys
/api/Addresss
/api/Quantitys
/api/Challenges
/b2b/v2/orders (XXE via XML order)
/file-upload (unrestricted upload)
/profile (SSRF via image URL)
/profile/image/file
/profile/image/url (SSRF)
/redirect?to= (open redirect, whitelist bypass)
/dataerasure
/ftp/ (directory listing)
/ftp/acquisitions.md (confidential)
/ftp/coupons_2013.md.bak (%2500 null byte bypass)
/ftp/eastere.gg (%2500 bypass)
/ftp/encrypt.pyc
/ftp/incident-support.kdbx
/ftp/package.json.bak
/ftp/quarantine/ (poison null byte)
/ftp/suspicious_errors.yml
/encryptionkeys/
/encryptionkeys/jwt.pub (JWT public key)
/support/logs
/support/logs/access.log.{date}
/metrics (Prometheus)
/snippets
/snippets/{id}
/assets/public/images/uploads/
/.well-known/security.txt
/video (streaming - range header DOS)
/promotion (video URL)
/accounting (admin only)
/privacy-security/last-login-ip
```

### 6. Finding Categories to Cover
For each finding, categorize properly:
- A1: Injection (SQLi, NoSQLi, Command, SSTI, XXE, XSS)
- A2: Broken Authentication (default creds, weak JWT, password reset)
- A3: Sensitive Data Exposure (info leaks, crypto, logging)
- A4: XXE
- A5: Broken Access Control (IDOR, privilege escalation, missing auth)
- A6: Security Misconfiguration (headers, CORS, verbose errors, debug)
- A7: XSS (reflected, stored, DOM)
- A8: Insecure Deserialization
- A9: Known Vulnerable Components
- A10: Insufficient Logging

### 7. Implementation Notes
- Keep the existing loop engine structure
- Probers should be independent modules in `internal/red/probers/`
- Each prober implements a `Prober` interface: `Probe(ctx, target, endpoints) []Finding`
- The Red AI agent orchestrates all probers
- Increase max-loops default to 5
- Each loop should focus on different technique categories
- First loop: unauthenticated broad scan
- Second loop: authenticated deep scan
- Third+ loops: technique-specific deep dives

### 8. Quality Rules
- Every finding MUST have: title, severity, endpoint, method, CWE, description, evidence from actual HTTP response
- Findings with actual exploit evidence (response body proving the vuln) = confirmed
- Findings based on header analysis or pattern matching = confirmed (lower confidence)
- NO theoretical/speculative findings — only things we can prove with HTTP responses

### 9. Testing
After implementation, run:
```bash
./ouroboros scan http://localhost:3000 --max-loops 5 --provider openai --model gpt-4o -o /tmp/ouroboros-80-test.md
```
Target: 80+ unique findings, 60%+ confirmed

### 10. Fix Blue AI JSON parsing bug
The Blue AI response parser fails on escape characters. Make it more robust.

## Files to Create/Modify
- CREATE: `internal/red/probers/prober.go` (interface)
- CREATE: `internal/red/probers/sqli.go`
- CREATE: `internal/red/probers/xss.go`
- CREATE: `internal/red/probers/idor.go`
- CREATE: `internal/red/probers/auth.go`
- CREATE: `internal/red/probers/infoleaks.go`
- CREATE: `internal/red/probers/injection.go`
- CREATE: `internal/red/probers/headers.go`
- CREATE: `internal/red/probers/fileupload.go`
- CREATE: `internal/red/probers/ssrf.go`
- CREATE: `internal/red/probers/crypto.go`
- MODIFY: `internal/red/agent.go` (integrate probers)
- MODIFY: `internal/red/crawler.go` (add Juice Shop specific paths)
- MODIFY: `internal/engine/loop.go` (authenticated scanning flow)
- MODIFY: `internal/blue/agent.go` (fix JSON parsing)
- MODIFY: `cmd/ouroboros/main.go` (update defaults)
- MODIFY: `internal/report/findings.go` (better output for 80+ findings)

## IMPORTANT
- This must COMPILE and WORK
- Run `go build ./cmd/ouroboros/` before finishing
- Test with: `./ouroboros scan http://localhost:3000 --max-loops 3 --provider openai --model gpt-4o`
- The binary must produce 80+ findings
