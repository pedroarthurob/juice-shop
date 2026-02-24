# OWASP Juice Shop — Manual Security Review (LLM Report)

## Scope & methodology

- **Scope**: Reviewed backend TypeScript source (`app.ts`, `server.ts`, `routes/`, `lib/`, `models/`, `data/`), server-side templates (`views/`), frontend Angular source (`frontend/src/`), and configuration (`config/`).  
- **Out of scope**: The `results/` directory was intentionally excluded.
- **Method**: Manual review + targeted pattern searches for injection sinks, XSS sinks, auth/session handling, secrets, crypto, CSRF, redirects, and sensitive data exposure.

## Findings

### 1) Hardcoded JWT signing private key (token forgery)

- **Vulnerability type**: Hardcoded secret / Authentication bypass
- **Severity**: **Critical**
- **File path & line(s)**: `lib/insecurity.ts` (L22-L57)
- **Code snippet**:

```ts
export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+R...'
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```

- **Technical explanation**: The RSA private key used to sign JWTs is embedded directly in source control. Anyone with repository access can mint valid tokens for arbitrary users/roles.
- **Realistic attack scenario**: An attacker generates an `admin` JWT offline using the embedded private key and sends requests with `Authorization: Bearer <forged>` to access protected endpoints (`security.isAuthorized()` middleware), achieving full privilege escalation.
- **Recommended fix**:
  - Remove private keys from the codebase entirely.
  - Load signing keys from a secrets manager or environment variables and rotate existing keys.
  - Add key rotation support (kid header + JWKS) if needed.
- **Confidence**: **High**

---

### 2) SQL injection in login endpoint

- **Vulnerability type**: SQL injection
- **Severity**: **Critical**
- **File path & line(s)**: `routes/login.ts` (L32-L55, especially L34)
- **Code snippet**:

```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

- **Technical explanation**: User-controlled `email` is interpolated directly into a SQL query string. This allows attackers to alter query structure (e.g., tautologies/UNION) and bypass authentication or extract data.
- **Realistic attack scenario**: Submit an email like `' OR 1=1--` to force the query to return a user record and obtain a valid JWT for that account.
- **Recommended fix**:
  - Use parameterized queries/bind variables (Sequelize replacements) or model-based queries (`UserModel.findOne({ where: ... })`).
  - Enforce strict input validation and centralized query builders.
- **Confidence**: **High**

---

### 3) SQL injection in product search

- **Vulnerability type**: SQL injection
- **Severity**: **Critical**
- **File path & line(s)**: `routes/search.ts` (L20-L31, especially L23)
- **Code snippet**:

```ts
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

- **Technical explanation**: User-controlled `criteria` (`req.query.q`) is concatenated into a SQL query, allowing injection (including UNION-based exfiltration from other tables).
- **Realistic attack scenario**: An attacker crafts a UNION payload in `q` to extract user emails/password hashes via the search API response.
- **Recommended fix**:
  - Use replacements/parameters for LIKE clauses, e.g. `... WHERE name LIKE :q` with `q: '%' + criteria + '%'`.
  - Consider full-text search or ORM query builders.
- **Confidence**: **High**

---

### 4) Sensitive directories exposed via directory listing and direct file serving

- **Vulnerability type**: Broken access control / Sensitive data exposure
- **Severity**: **Critical**
- **File path & line(s)**:
  - `server.ts` (L267-L284, L276-L279)
  - `routes/keyServer.ts` (L9-L18)
  - `routes/logfileServer.ts` (L9-L18)
- **Code snippet**:

```ts
app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))
app.use('/encryptionkeys/:file', serveKeyFiles())
app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' }))
app.use('/support/logs/:file', serveLogFiles())
```

- **Technical explanation**: The application publishes directory browsing and direct download endpoints for `encryptionkeys/` and `logs/`, which commonly contain cryptographic material and sensitive operational data.
- **Realistic attack scenario**: An attacker downloads JWT public keys and/or operational logs. Logs often contain request metadata, tokens, emails, and stack traces; keys can enable further attacks depending on usage.
- **Recommended fix**:
  - Remove these routes in non-training deployments.
  - If needed for admin/support, require strong authentication + authorization and disable `serve-index`.
  - Ensure secrets/keys are never readable from the web root.
- **Confidence**: **High**

---

### 5) Open redirect due to substring allowlist check

- **Vulnerability type**: Open redirect
- **Severity**: **High**
- **File path & line(s)**:
  - `lib/insecurity.ts` (L124-L141)
  - `routes/redirect.ts` (L13-L23)
- **Code snippet**:

```ts
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
```

- **Technical explanation**: Using `url.includes(allowedUrl)` allows attacker-controlled URLs that merely *contain* an allowlisted string (e.g., `https://evil.tld/?next=https://github.com/juice-shop/juice-shop`) to pass validation.
- **Realistic attack scenario**: A phishing campaign links to `GET /redirect?to=<attacker-url-containing-allowlisted-substring>`, leveraging the legitimate domain to increase user trust.
- **Recommended fix**:
  - Parse and compare origins/hosts exactly (e.g., `new URL(toUrl)`), and enforce `https` and exact host allowlists.
  - Use strict prefix checks for full URLs only if you fully control the allowlist and normalize input (still prefer URL parsing).
- **Confidence**: **High**

---

### 6) Unauthenticated exposure of full runtime configuration

- **Vulnerability type**: Sensitive data exposure / Authorization flaw
- **Severity**: **High**
- **File path & line(s)**:
  - `routes/appConfiguration.ts` (L6-L12)
  - `server.ts` (L599-L601)
- **Code snippet**:

```ts
export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    res.json({ config })
  }
}
// ...
app.get('/rest/admin/application-configuration', retrieveAppConfiguration())
```

- **Technical explanation**: An endpoint under an `/admin/` URL path returns the entire `config` object without any authentication/authorization middleware.
- **Realistic attack scenario**: An unauthenticated attacker retrieves internal settings (feature flags, environment-specific URLs, safety mode, and other configuration). In real systems, config often contains secrets or endpoints not meant for public exposure.
- **Recommended fix**:
  - Require authentication and restrict to admin role server-side.
  - Return only a minimal, explicitly allowlisted subset of configuration needed by the frontend.
- **Confidence**: **High**

---

### 7) Server-Side Request Forgery (SSRF) via profile image URL upload

- **Vulnerability type**: SSRF
- **Severity**: **High**
- **File path & line(s)**: `routes/profileImageUrlUpload.ts` (L16-L36)
- **Code snippet**:

```ts
const url = req.body.imageUrl
const response = await fetch(url)
// ...
const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
```

- **Technical explanation**: The server fetches an arbitrary URL provided by the user. This enables requests to internal services (e.g., cloud metadata endpoints, internal admin panels), potentially disclosing data or enabling pivoting.
- **Realistic attack scenario**: An attacker submits `http://127.0.0.1:...` or `http://169.254.169.254/...` as `imageUrl` and the server fetches sensitive internal content.
- **Recommended fix**:
  - Enforce strict URL allowlists (scheme/host), block private IP ranges, and disable redirects.
  - Use a safe image proxy service or fetch via an outbound egress proxy with SSRF protections.
  - Validate content-type and size before writing to disk.
- **Confidence**: **High**

---

### 8) Content-Security-Policy (CSP) header injection via user-controlled `profileImage`

- **Vulnerability type**: Header injection / XSS defense bypass
- **Severity**: **High**
- **File path & line(s)**:
  - `routes/userProfile.ts` (L86-L99)
  - `routes/profileImageUrlUpload.ts` (L33-L36)
- **Code snippet**:

```ts
const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval' https://code.getmdl.io http://ajax.googleapis.com`
res.set({ 'Content-Security-Policy': CSP })
// ...
await user?.update({ profileImage: url })
```

- **Technical explanation**: `profileImage` can be set to an arbitrary string/URL and is concatenated into a CSP header without sanitization or quoting. This allows an attacker to inject additional CSP directives (e.g., enabling `unsafe-inline`) and weaken the page’s XSS protections.
- **Realistic attack scenario**: An attacker sets `profileImage` to a value containing `; script-src 'unsafe-inline' ...` so subsequent visits to `/profile` accept inline scripts, amplifying any stored/reflected HTML injection into full XSS.
- **Recommended fix**:
  - Never concatenate untrusted values into HTTP response headers.
  - Build CSP using a library, and only allow `profileImage` values that match a strict URL pattern (or better: store only server-generated relative paths).
- **Confidence**: **High**

---

### 9) Server-side code execution via `eval()` in profile username processing (challenge-gated)

- **Vulnerability type**: Code injection / RCE
- **Severity**: **Critical**
- **File path & line(s)**: `routes/userProfile.ts` (L55-L68, especially L62)
- **Code snippet**:

```ts
if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
  const code = username?.substring(2, username.length - 1)
  username = eval(code)
}
```

- **Technical explanation**: When the challenge is enabled, user-controlled `username` content is executed with `eval()` on the server, enabling arbitrary JavaScript execution within the Node.js process.
- **Realistic attack scenario**: An attacker sets their username to `#{process.mainModule.require('child_process').execSync('id').toString()}` (or equivalent) and triggers code execution on the server when `/profile` is rendered.
- **Recommended fix**:
  - Remove `eval()` and any execution of user-supplied code.
  - If templating is required, use a safe templating mechanism with strict escaping and no code execution.
- **Confidence**: **High**

---

### 10) Zip Slip / arbitrary file write during ZIP upload (challenge-gated)

- **Vulnerability type**: Arbitrary file write (path traversal in archive extraction)
- **Severity**: **Critical**
- **File path & line(s)**: `routes/fileUpload.ts` (L27-L49)
- **Code snippet**:

```ts
.on('entry', function (entry: any) {
  const fileName = entry.path
  const absolutePath = path.resolve('uploads/complaints/' + fileName)
  if (absolutePath.includes(path.resolve('.'))) {
    entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))
  } else {
    entry.autodrain()
  }
})
```

- **Technical explanation**: `entry.path` is used directly to construct a filesystem path. The `absolutePath.includes(path.resolve('.'))` check does not prevent `../` traversal. Attackers can write files outside the intended directory by crafting ZIP entries such as `../../some/target`.
- **Realistic attack scenario**: Upload a ZIP containing an entry that overwrites an application file or drops a malicious file into a served directory. This can lead to defacement, data corruption, or code execution depending on deployment.
- **Recommended fix**:
  - Reject ZIP entries containing `..`, absolute paths, or path separators after normalization.
  - Use a hardened unzip library/pattern that validates the final resolved path stays within the destination directory.
- **Confidence**: **High**

---

### 11) XXE (XML External Entity expansion) via libxml parsing (challenge-gated)

- **Vulnerability type**: Injection (XXE)
- **Severity**: **High**
- **File path & line(s)**: `routes/fileUpload.ts` (L75-L99, especially L83-L87)
- **Code snippet**:

```ts
const xmlDoc = vm.runInContext(
  'libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })',
  sandbox,
  { timeout: 2000 }
)
```

- **Technical explanation**: `noent: true` enables entity substitution. If external entities are permitted by the XML parser/environment, this can enable file disclosure or network access via crafted XML.
- **Realistic attack scenario**: Upload XML containing an external entity referencing local files; the parsed output is included in an error message, disclosing sensitive content.
- **Recommended fix**:
  - Disable entity expansion and DTD processing (`noent: false`, disallow DTDs).
  - Use secure XML parsers configured to block XXE by default.
- **Confidence**: **Medium** (depends on libxml configuration/runtime behavior, but the entity-expansion setting is explicit)

---

### 12) NoSQL injection / server-side JS execution via `$where` string concatenation (challenge-gated)

- **Vulnerability type**: NoSQL injection (server-side JS predicate)
- **Severity**: **High**
- **File path & line(s)**: `routes/showProductReviews.ts` (L28-L38, especially L36)
- **Code snippet**:

```ts
const id = !utils.isChallengeEnabled(challenges.noSqlCommandChallenge) ? Number(req.params.id) : utils.trunc(req.params.id, 40)
db.reviewsCollection.find({ $where: 'this.product == ' + id })
```

- **Technical explanation**: When the challenge is enabled, a user-controlled string is concatenated into a `$where` JavaScript expression. This enables injection of additional code and can lead to denial of service (and potentially worse, depending on the underlying engine).
- **Realistic attack scenario**: Request `/rest/products/<payload>/reviews` with a payload that causes expensive evaluation (or `sleep(...)`), degrading availability.
- **Recommended fix**:
  - Remove `$where` usage entirely; use structured queries (e.g., `{ product: Number(id) }`).
  - Enforce strict numeric parsing regardless of challenge settings.
- **Confidence**: **High**

---

### 13) Mass update / unauthorized modification risk in review update endpoint

- **Vulnerability type**: Authorization flaw / NoSQL injection vector
- **Severity**: **High**
- **File path & line(s)**: `routes/updateProductReviews.ts` (L14-L28)
- **Code snippet**:

```ts
db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } },
  { multi: true }
)
```

- **Technical explanation**: The update selector is derived directly from request body. If the datastore accepts operator objects, attackers may supply a selector that matches multiple documents. Additionally, there is no ownership check to ensure the caller is allowed to modify the referenced review.
- **Realistic attack scenario**: An authenticated attacker updates or defaces other users’ reviews by targeting their IDs, and may attempt broader updates if selector operators are accepted by the DB layer.
- **Recommended fix**:
  - Validate `id` is a strict scalar identifier.
  - Enforce ownership/authorization checks (review author must match caller).
  - Remove `multi: true` unless explicitly required with strong constraints.
- **Confidence**: **Medium** (depends on datastore operator semantics; lack of authz check is clear)

---

### 14) Forged/unauthenticated product reviews (missing server-side author enforcement)

- **Vulnerability type**: Authentication/authorization flaw (impersonation)
- **Severity**: **High**
- **File path & line(s)**:
  - `server.ts` (L626-L630)
  - `routes/createProductReviews.ts` (L14-L31)
- **Code snippet**:

```ts
app.put('/rest/products/:id/reviews', createProductReviews())
// ...
await reviewsCollection.insert({
  product: req.params.id,
  message: req.body.message,
  author: req.body.author,
  likesCount: 0,
  likedBy: []
})
```

- **Technical explanation**: The review creation endpoint is mounted without an auth middleware and accepts an `author` field from the client. This enables anonymous posting and author spoofing.
- **Realistic attack scenario**: An attacker posts reviews as `admin@...` (or any victim) to mislead users, poison moderation workflows, or plant payloads for downstream XSS sinks.
- **Recommended fix**:
  - Require authentication for review creation.
  - Derive `author` from the authenticated identity server-side (ignore client-supplied author).
  - Apply output encoding and/or HTML sanitization for `message`.
- **Confidence**: **High**

---

### 15) Basket manipulation via duplicate JSON keys (logic flaw)

- **Vulnerability type**: Business logic flaw (parameter pollution)
- **Severity**: **High**
- **File path & line(s)**: `routes/basketItems.ts` (L19-L54)
- **Code snippet**:

```ts
const result = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
// ...
if (user && basketIds[0] && Number(user.bid) != Number(basketIds[0])) {
  res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
} else {
  const basketItem = {
    BasketId: basketIds[basketIds.length - 1],
    // ...
  }
  BasketItemModel.build(basketItem).save()
}
```

- **Technical explanation**: The validation checks the *first* observed `BasketId`, but the code uses the *last* `BasketId` when constructing the basket item. By sending multiple `BasketId` keys in the raw JSON payload, an attacker can pass validation and then target a different basket.
- **Realistic attack scenario**: An authenticated attacker adds/removes items in another user’s basket by crafting a payload with two `BasketId` fields: the first set to their own basket, the second set to the victim basket.
- **Recommended fix**:
  - Use standard JSON parsing and reject duplicate keys.
  - Validate and use a single canonical `BasketId` value.
  - Enforce basket ownership server-side by looking up the basket by authenticated user ID.
- **Confidence**: **High**

---

### 16) CSRF on `/profile` update + insecure JWT cookie attributes

- **Vulnerability type**: CSRF / Insecure session handling
- **Severity**: **High**
- **File path & line(s)**:
  - `routes/updateUserProfile.ts` (L14-L43)
  - `lib/insecurity.ts` (L188-L200)
- **Code snippet**:

```ts
// Cookie-based auth usage
const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
// ...
const updatedToken = security.authorize(userWithStatus)
res.cookie('token', updatedToken)
```

- **Technical explanation**: Profile updates rely on a cookie token without CSRF protections (no CSRF token, no same-site enforcement shown) and set cookies without explicit `HttpOnly`, `Secure`, or `SameSite` attributes. This enables cross-site requests to perform state changes when the browser automatically includes cookies, and increases token theft risk under XSS.
- **Realistic attack scenario**: A malicious site causes a logged-in user’s browser to submit a POST to `/profile` that changes the username (or other fields) without user intent.
- **Recommended fix**:
  - Add CSRF protection (synchronizer token or double-submit cookie) for cookie-authenticated endpoints.
  - Set cookies with `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict` where possible).
  - Prefer Authorization headers over cookies for APIs, or require explicit anti-CSRF headers.
- **Confidence**: **High**

---

### 17) Rate-limit bypass by trusting `X-Forwarded-For` header

- **Vulnerability type**: Authentication protection bypass (brute force / rate limit evasion)
- **Severity**: **High**
- **File path & line(s)**: `server.ts` (L338-L342)
- **Code snippet**:

```ts
app.use('/rest/user/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }
}))
```

- **Technical explanation**: The rate limit key is derived from a user-controlled header. Attackers can spoof `X-Forwarded-For` to rotate identities and bypass throttling.
- **Realistic attack scenario**: An attacker automates password reset attempts (security-question answers) and changes `X-Forwarded-For` on every request to avoid hitting the per-IP cap.
- **Recommended fix**:
  - Only trust `X-Forwarded-For` when behind a trusted proxy and with correct `trust proxy` configuration, and use a validated library to extract the real client IP.
  - Consider rate limiting by account/email as well as IP.
- **Confidence**: **High**

---

### 18) Insecure password hashing using MD5

- **Vulnerability type**: Insecure cryptographic usage
- **Severity**: **High**
- **File path & line(s)**:
  - `lib/insecurity.ts` (L43)
  - `models/user.ts` (L74-L79)
- **Code snippet**:

```ts
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
// ...
this.setDataValue('password', security.hash(clearTextPassword))
```

- **Technical explanation**: MD5 is a fast, unsalted hash and is unsuitable for password storage. It is vulnerable to brute-force attacks and rainbow tables.
- **Realistic attack scenario**: If the user table is exfiltrated (e.g., via SQL injection), attackers can crack many passwords quickly and reuse them on other services.
- **Recommended fix**:
  - Use a modern password hashing function (Argon2id, bcrypt, or scrypt) with a per-user salt and appropriate work factor.
  - Migrate hashes safely (rehash on next login).
- **Confidence**: **High**

---

### 19) Hardcoded credentials in authentication-related code paths

- **Vulnerability type**: Hardcoded credentials / Sensitive data exposure
- **Severity**: **Medium**
- **File path & line(s)**:
  - `routes/login.ts` (L59-L67)
  - `frontend/src/app/login/login.component.ts` (L60-L62)
- **Code snippet**:

```ts
challengeUtils.solveIf(challenges.loginSupportChallenge, () => {
  return req.body.email === 'support@' + config.get<string>('application.domain') && req.body.password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
})
// ...
public testingUsername = 'testing@juice-sh.op'
public testingPassword = 'IamUsedForTesting'
```

- **Technical explanation**: Literal passwords are present in source code. Even if intended for training, this pattern is high-risk in real deployments and often results in credential reuse and accidental exposure.
- **Realistic attack scenario**: Attackers scan public repos for password patterns and try them against live instances or other systems where developers reused credentials.
- **Recommended fix**:
  - Remove plaintext passwords from source.
  - Use test fixtures and environment-provided secrets for non-production training accounts.
- **Confidence**: **High**

---

### 20) DOM XSS in search results by bypassing Angular sanitization

- **Vulnerability type**: Cross-Site Scripting (DOM XSS)
- **Severity**: **High**
- **File path & line(s)**:
  - `frontend/src/app/search-result/search-result.component.ts` (L143-L172)
  - `frontend/src/app/search-result/search-result.component.html` (L10-L15)
- **Code snippet**:

```ts
tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
// ...
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
```

```html
<span id="searchValue" [innerHTML]="searchValue"></span>
```

- **Technical explanation**: `bypassSecurityTrustHtml` disables Angular’s built-in HTML sanitization. Rendering the result via `[innerHTML]` makes any injected HTML/JS execute in the browser if attacker-controlled content reaches these fields (notably query parameters and server-provided product descriptions).
- **Realistic attack scenario**:
  - **Reflected**: Attacker sends a victim a link such as `/#/search?q=<img src=x onerror=alert(1)>` leading to XSS.
  - **Stored**: If product descriptions can be tampered with (e.g., via backend SQL injection), XSS persists for all viewers.
- **Recommended fix**:
  - Do not use `bypassSecurityTrustHtml` on untrusted content.
  - Render text-only, or sanitize with a robust HTML sanitizer (and still prefer safe components).
- **Confidence**: **High**

---

### 21) DOM XSS in admin/feedback views by bypassing Angular sanitization

- **Vulnerability type**: Cross-Site Scripting (DOM XSS)
- **Severity**: **High**
- **File path & line(s)**:
  - `frontend/src/app/administration/administration.component.ts` (L54-L81)
  - `frontend/src/app/administration/administration.component.html` (L24-L27, L57-L61)
  - `frontend/src/app/about/about.component.ts` (L113-L126)
  - `frontend/src/app/about/about.component.html` (L49-L52)
- **Code snippet**:

```ts
user.email = this.sanitizer.bypassSecurityTrustHtml(`<span class="...">${user.email}</span>`)
feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment)
// ...
feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(feedbacks[i].comment)
```

```html
<mat-cell *matCellDef="let user" [innerHTML]="user.email"></mat-cell>
<p [innerHTML]="feedback.comment"></p>
<figure class="feedback" [innerHTML]="item?.args"></figure>
```

- **Technical explanation**: Untrusted data (user emails, feedback comments) is rendered as trusted HTML. If an attacker can insert HTML into these fields (e.g., via registration/feedback endpoints), this becomes stored XSS that executes for admin and end users.
- **Realistic attack scenario**: Attacker submits feedback containing an event-handler payload; when an admin opens the administration page or the about page carousel, the payload runs and steals tokens from `localStorage`.
- **Recommended fix**:
  - Avoid `[innerHTML]` for user content.
  - Encode output or sanitize with an allowlist-based sanitizer, and remove `bypassSecurityTrustHtml`.
- **Confidence**: **High**

---

### 22) DOM XSS in “Last Login IP” display via trusted HTML from JWT payload

- **Vulnerability type**: Cross-Site Scripting (DOM XSS)
- **Severity**: **High**
- **File path & line(s)**:
  - `frontend/src/app/last-login-ip/last-login-ip.component.ts` (L32-L40)
  - `frontend/src/app/last-login-ip/last-login-ip.component.html` (L8-L11)
- **Code snippet**:

```ts
payload = jwtDecode(token)
this.lastLoginIp = this.sanitizer.bypassSecurityTrustHtml(`<small>${payload.data.lastLoginIp}</small>`)
```

```html
<dd [innerHTML]="lastLoginIp"></dd>
```

- **Technical explanation**: The UI renders `lastLoginIp` from the JWT payload as trusted HTML. If an attacker can influence `lastLoginIp` (e.g., via the `true-client-ip` header persisted on the server), this becomes stored XSS.
- **Realistic attack scenario**: Attacker sets a malicious `true-client-ip` header on login, then the victim views the “Last Login IP” page and executes the injected payload.
- **Recommended fix**:
  - Treat JWT payload data as untrusted.
  - Render it as text (no HTML), and do not bypass sanitization.
- **Confidence**: **High**

---

### 23) Tokens stored in `localStorage` and injected into every request

- **Vulnerability type**: Insecure session handling / Token theft amplification
- **Severity**: **Medium**
- **File path & line(s)**:
  - `frontend/src/app/login/login.component.ts` (L95-L106)
  - `frontend/src/app/two-factor-auth-enter/two-factor-auth-enter.component.ts` (L51-L58)
  - `frontend/src/app/Services/request.interceptor.ts` (L12-L19)
- **Code snippet**:

```ts
localStorage.setItem('token', authentication.token)
```

```ts
Authorization: `Bearer ${localStorage.getItem('token')}`
```

- **Technical explanation**: Storing bearer tokens in `localStorage` makes them accessible to any successful XSS payload. The interceptor then automatically replays that token to backend APIs, turning any XSS into full account takeover.
- **Realistic attack scenario**: A stored DOM-XSS payload reads `localStorage.token` and exfiltrates it. The attacker reuses the token for authenticated API calls until expiry.
- **Recommended fix**:
  - Prefer `HttpOnly` secure cookies for session tokens (with CSRF defenses), or store tokens in memory only.
  - Reduce token lifetime and implement refresh token rotation.
- **Confidence**: **High**

---

### 24) Potential local file inclusion via `layout` parameter during data erasure rendering

- **Vulnerability type**: Local file inclusion (template/layout manipulation)
- **Severity**: **High**
- **File path & line(s)**: `routes/dataErasure.ts` (L67-L90)
- **Code snippet**:

```ts
if (req.body.layout) {
  const filePath: string = path.resolve(req.body.layout).toLowerCase()
  const isForbiddenFile: boolean = (filePath.includes('ftp') || filePath.includes('ctf.key') || filePath.includes('encryptionkeys'))
  if (!isForbiddenFile) {
    res.render('dataErasureResult', { ...req.body }, (error, html) => {
      const sendlfrResponse: string = html.slice(0, 100) + '......'
      res.send(sendlfrResponse)
    })
  }
}
```

- **Technical explanation**: User input is used to influence rendering options via the `layout` field. The code attempts to block a few substrings but does not enforce an allowlist of valid templates. In many Express view engines, `layout` controls which template file is used, enabling file inclusion.
- **Realistic attack scenario**: An attacker submits a crafted `layout` value pointing to a local file; the rendering engine attempts to load it, potentially disclosing file contents (partially returned in the response).
- **Recommended fix**:
  - Do not allow clients to set template/layout selection.
  - Use a strict allowlist of layout names (not filesystem paths) if dynamic layouts are needed.
- **Confidence**: **Medium** (depends on view engine behavior; the untrusted layout parameter is clear)

---

### 25) Overly permissive CORS configuration

- **Vulnerability type**: Cross-origin access control weakness
- **Severity**: **Medium**
- **File path & line(s)**: `server.ts` (L180-L183)
- **Code snippet**:

```ts
app.options('*', cors())
app.use(cors())
```

- **Technical explanation**: CORS is enabled globally with default permissive behavior. While not inherently exploitable alone, in combination with token/cookie handling and missing CSRF protections it increases the attack surface and can enable cross-origin interactions that were not intended.
- **Realistic attack scenario**: A malicious origin interacts with APIs from a victim’s browser more easily (especially when other misconfigurations exist), contributing to exploitation chains.
- **Recommended fix**:
  - Restrict allowed origins, methods, and headers to known frontends.
  - Avoid wildcard CORS for authenticated endpoints.
- **Confidence**: **Medium**

---

### 26) Hardcoded HMAC secret used for security-sensitive operations

- **Vulnerability type**: Hardcoded secret / Insecure cryptographic usage
- **Severity**: **High**
- **File path & line(s)**: `lib/insecurity.ts` (L44-L45)
- **Code snippet**:

```ts
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')
```

- **Technical explanation**: A static HMAC key is hardcoded in the repository. Any attacker with code access can compute valid HMACs for any input, undermining integrity checks that rely on this function (e.g., security-answer verification).
- **Realistic attack scenario**: If HMAC values are used to validate user-provided secrets (such as security question answers), an attacker can generate matching HMACs offline and bypass checks.
- **Recommended fix**:
  - Load HMAC keys from environment/secrets manager, rotate them, and ensure they are not committed.
  - Prefer per-user salts/secrets for sensitive verifications where applicable.
- **Confidence**: **High**

---

### 27) Hardcoded cookie signing secret

- **Vulnerability type**: Hardcoded secret / Insecure session handling
- **Severity**: **Medium**
- **File path & line(s)**: `server.ts` (L288-L290)
- **Code snippet**:

```ts
app.use(express.static(path.resolve('frontend/dist/frontend')))
app.use(cookieParser('kekse'))
```

- **Technical explanation**: A fixed cookie-parser secret enables predictable signing. If signed cookies are used for security decisions, an attacker can potentially forge them when the secret is known.
- **Realistic attack scenario**: In deployments where signed cookies influence authentication/authorization, attackers with the secret can craft valid signed cookies to tamper with server-side logic.
- **Recommended fix**:
  - Move secrets to environment/secrets manager and rotate.
  - Avoid using signed cookies for auth unless combined with strong server-side validation.
- **Confidence**: **Medium** (depends on whether signed cookies are relied on for security decisions)

---

### 28) Password change endpoint uses GET query parameters (credential leakage)

- **Vulnerability type**: Sensitive data exposure
- **Severity**: **Medium**
- **File path & line(s)**: `routes/changePassword.ts` (L12-L25)
- **Code snippet**:

```ts
const currentPassword = query.current as string
const newPassword = query.new as string
const repeatPassword = query.repeat
```

- **Technical explanation**: Passwords passed in query parameters are commonly logged (access logs, proxies), stored in browser history, and leaked via Referer headers on subsequent requests.
- **Realistic attack scenario**: A reverse proxy, CDN, or server access log retains `?new=<password>` allowing later recovery by anyone with log access.
- **Recommended fix**:
  - Use `POST` with a JSON body for password changes.
  - Ensure request logging excludes sensitive fields.
- **Confidence**: **High**

---

### 29) Prometheus metrics exposed without authentication

- **Vulnerability type**: Sensitive information exposure
- **Severity**: **Medium**
- **File path & line(s)**:
  - `server.ts` (L709-L714)
  - `routes/metrics.ts` (L66-L75)
- **Code snippet**:

```ts
app.get('/metrics', metrics.serveMetrics())
```

```ts
res.end(await register.metrics())
```

- **Technical explanation**: Operational metrics are exposed over HTTP without access controls. Depending on what is collected, this can leak internal application behavior, counts, and system information useful for attackers.
- **Realistic attack scenario**: An attacker scrapes `/metrics` to learn request volumes, challenge/feature state, and other signals that assist targeted exploitation or DoS planning.
- **Recommended fix**:
  - Restrict `/metrics` to internal networks or require authentication (mTLS, basic auth, or token).
  - Consider separate listener/port bound to localhost for metrics.
- **Confidence**: **High**

---

## Summary table (grouped by severity)

| Severity | Finding |
|---|---|
| **Critical** | Hardcoded JWT signing private key (`lib/insecurity.ts`) |
| **Critical** | SQL injection in login (`routes/login.ts`) |
| **Critical** | SQL injection in product search (`routes/search.ts`) |
| **Critical** | Sensitive directories exposed (`server.ts`, `routes/keyServer.ts`, `routes/logfileServer.ts`) |
| **Critical** | Server-side `eval()` (challenge-gated) (`routes/userProfile.ts`) |
| **Critical** | Zip Slip arbitrary file write (challenge-gated) (`routes/fileUpload.ts`) |
| **High** | Open redirect (`lib/insecurity.ts`, `routes/redirect.ts`) |
| **High** | Unauthenticated config exposure (`routes/appConfiguration.ts`, `server.ts`) |
| **High** | SSRF via profile image URL (`routes/profileImageUrlUpload.ts`) |
| **High** | CSP header injection (`routes/userProfile.ts`, `routes/profileImageUrlUpload.ts`) |
| **High** | XXE settings enabled (challenge-gated) (`routes/fileUpload.ts`) |
| **High** | NoSQL `$where` injection (challenge-gated) (`routes/showProductReviews.ts`) |
| **High** | Review update authorization/injection risk (`routes/updateProductReviews.ts`) |
| **High** | Forged/unauthenticated reviews (`server.ts`, `routes/createProductReviews.ts`) |
| **High** | Basket parameter pollution (`routes/basketItems.ts`) |
| **High** | CSRF + weak cookie attributes (`routes/updateUserProfile.ts`, `lib/insecurity.ts`) |
| **High** | Rate-limit bypass via `X-Forwarded-For` (`server.ts`) |
| **High** | MD5 password hashing (`lib/insecurity.ts`, `models/user.ts`) |
| **High** | DOM XSS in search (`frontend/src/app/search-result/...`) |
| **High** | DOM XSS in admin/about (`frontend/src/app/administration/...`, `frontend/src/app/about/...`) |
| **High** | DOM XSS via last-login-ip (`frontend/src/app/last-login-ip/...`) |
| **High** | Data erasure layout injection/LFI risk (`routes/dataErasure.ts`) |
| **High** | Hardcoded HMAC secret (`lib/insecurity.ts`) |
| **Medium** | Hardcoded credentials (`routes/login.ts`, `frontend/src/app/login/login.component.ts`) |
| **Medium** | Token in `localStorage` + interceptor replay (`frontend/src/app/...`, `frontend/src/app/Services/request.interceptor.ts`) |
| **Medium** | Overly permissive CORS (`server.ts`) |
| **Medium** | Hardcoded cookie signing secret (`server.ts`) |
| **Medium** | Passwords in query parameters (`routes/changePassword.ts`) |
| **Medium** | Unauthenticated Prometheus metrics (`server.ts`, `routes/metrics.ts`) |

## Total findings

**29**

## Overall security posture assessment

The codebase contains **multiple direct, high-impact vulnerabilities** across authentication, injection (SQL/NoSQL/XXE), XSS (multiple DOM-XSS sinks with explicit sanitizer bypass), sensitive data exposure, and CSRF/session handling. Several issues are **individually sufficient for full account takeover or server compromise** (e.g., hardcoded JWT signing key, SQL injection, server-side `eval`, arbitrary file write). Overall posture is **intentionally insecure** and would be **unsafe for any production deployment** without substantial hardening and removal of challenge/vulnerable code paths.

