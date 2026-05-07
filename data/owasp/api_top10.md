# OWASP API Security Top 10 (2023)

Reference knowledge base for ARIA. Each section covers one OWASP API Security
category with description, attack techniques, example payloads, detection
indicators, and remediation guidance.

## API1:2023 — Broken Object Level Authorization (BOLA)

### Description
BOLA (also called IDOR — Insecure Direct Object Reference) occurs when an API
endpoint exposes object identifiers in requests and fails to validate that the
requesting user is authorized to access the specific object. It is consistently
the most exploited API vulnerability class.

### Attack Techniques
- Horizontal privilege escalation: substitute the object ID in the path, query
  param, or request body with IDs belonging to other users at the same privilege level
- Integer enumeration: when IDs are sequential, test id-1, id+1, id-5, id+10,
  id+100 to discover adjacent records owned by other users
- UUID substitution: replace a valid UUID with other UUIDs observed in API responses
  (e.g., from list endpoints, error messages, or other users' links)
- Unauthenticated access: repeat the same request without the Authorization header
  to test whether the resource is publicly accessible
- Cross-tenant access: in multi-tenant systems, test IDs from one tenant against
  another tenant's authenticated session

### Example Payloads
GET /api/v1/users/123/profile → test with user_id 124, 125, 1, 2, 999, 0
GET /api/v1/orders/d290f1ee-6c54-4b01-90e6-d701748f0851 → test with other UUIDs
GET /api/v1/documents/42/download → repeat as a different authenticated user
PUT /api/v1/accounts/99/settings → test with foreign account IDs
GET /api/v1/invoices?customer_id=100 → change customer_id to other values

### Detection Indicators
- HTTP 200 with non-empty response body for a foreign user's resource ID
- Response body differs from the baseline (authenticated user's own resource)
- No 403 Forbidden or 404 Not Found returned for cross-user ID access
- Consistent response structure regardless of which user's ID is used
- Sensitive data (email, name, address) for a different user in the response

### Remediation
- Enforce object-level authorization on every endpoint: validate that the session
  user owns or has explicit permission for the requested object ID
- Use random UUIDs (v4) instead of sequential integer IDs to prevent enumeration
- Implement a centralized authorization middleware rather than ad-hoc per-endpoint checks
- Return 403 Forbidden (not 404) to avoid leaking resource existence
- Log all access attempts to object IDs not owned by the authenticated user

## API2:2023 — Broken Authentication

### Description
Broken Authentication encompasses weaknesses in token-based auth, session management,
credential handling, and identity verification. APIs that rely on JWT tokens are
particularly susceptible due to common implementation errors in JWT libraries.

### Attack Techniques
- JWT none-algorithm attack: change the `alg` header field to `none` and strip the
  signature entirely. Some JWT libraries accept unsigned tokens when alg=none.
- JWT algorithm confusion (RS256→HS256): change `alg` from RS256 to HS256 and
  sign the token using the server's RSA public key as the HMAC secret. The server
  may verify with its public key and accept the forged token.
- Weak JWT secret brute-force: try common secrets against HS256 tokens. Common
  secrets: secret, password, 123456, admin, key, jwt_secret, changeme,
  your-256-bit-secret, (empty string)
- Expired token reuse: remove the `exp` claim, set it to a far-future date, or
  re-encode the payload without re-signing to test expiry enforcement
- JWT claim manipulation: change sub, role, user_id, or admin fields in the payload
  after decoding, then re-encode and test whether the modified token is accepted
- Missing Authorization header: test authenticated endpoints with no token at all
- Default credentials: try admin:admin, admin:password, root:root, test:test, guest:guest

### Example Payloads
JWT with alg=none: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
JWT with role changed to admin in payload claims
Authorization header omitted entirely on protected endpoint
Expired JWT token resent as-is without modification

### Detection Indicators
- HTTP 200 on a protected endpoint when Authorization header is omitted
- HTTP 200 with a JWT whose alg=none and no signature
- HTTP 200 after changing role claim from user to admin in JWT payload
- JWT with an expired exp claim still accepted by the server
- Default credentials accepted on login or admin endpoints

### Remediation
- Validate JWT signature with strong algorithms: RS256 (asymmetric) or HS256 with
  a cryptographically random secret of at least 256 bits
- Always validate all standard claims: exp, nbf, iss, aud, and any custom claims
- Explicitly reject tokens with alg: none or any unexpected algorithm in a whitelist
- Use a well-audited JWT library; never implement signature verification manually
- Implement short token lifetimes (15 minutes for access tokens, rotation for refresh)
- Log and alert on repeated authentication failures

## API3:2023 — Broken Object Property Level Authorization

### Description
APIs may return more object properties than the consumer needs (excessive data
exposure) or may accept more properties on write operations than intended
(mass assignment). Both allow attackers to access or modify privileged data fields.

### Attack Techniques
- Sensitive field enumeration: inspect all API response bodies for fields not shown
  in the UI or documented in the spec: password_hash, secret, internal_notes, ssn,
  credit_card, api_key, admin, verified, role
- Response comparison: compare the raw API response to what the UI renders to find
  hidden fields the frontend intentionally suppresses
- Nested object inspection: check nested objects and arrays for sensitive sub-fields
  (e.g., user.payment_info.cvv)

### Sensitive Field Patterns to Flag
Fields matching: password, hash, secret, token, key, ssn, dob, credit, card,
internal, private, admin, role, permission, verified, balance, salary, pin

### Detection Indicators
- Response schema contains fields not documented in the API spec
- Fields with privileged or sensitive names appear in responses
- Response body is larger than expected for the stated use case
- Undocumented fields carry security-relevant values (role=admin, verified=true)

### Remediation
- Define strict response DTOs (Data Transfer Objects) that include only required fields
- Never serialize ORM model objects directly into API responses
- Apply field-level authorization: filter response properties based on the caller's role
- Use allowlist-based serialization; explicitly name every field that may be returned

## API4:2023 — Unrestricted Resource Consumption

### Description
APIs that lack rate limiting, request size limits, or resource quotas allow attackers
to exhaust server resources, brute-force credentials, enumerate data, and abuse
expensive operations. The absence of a 429 response is the primary indicator.

### Attack Techniques
- Rate limit absence test: send 50+ identical requests and verify no HTTP 429 received
- Authentication brute-force: attempt many passwords on login endpoints without lockout
- Credential stuffing: try credential pairs from breach databases without rate limit
- Resource enumeration: rapidly iterate through IDs to map all valid resources
- Expensive operation abuse: trigger computationally expensive endpoints repeatedly
- Large payload injection: send oversized request bodies to exhaust memory or CPU

### Example Payloads
50 identical GET requests to the same endpoint within 5 seconds
POST /api/v1/auth/login with 50 different passwords in rapid succession
GET /api/v1/reports/generate called 100 times concurrently

### Detection Indicators
- No HTTP 429 Too Many Requests returned after 50+ identical requests
- No Retry-After or X-RateLimit-* headers in any response
- Login endpoint allows unlimited password attempts with no delay or lockout
- All 50+ requests return HTTP 200 with identical response times

### Remediation
- Implement rate limiting per user, per IP, and per API key for all endpoints
- Return HTTP 429 with Retry-After header when limits are exceeded
- Apply stricter, separate limits on authentication, registration, and password reset
- Enforce request body size limits and maximum file upload sizes
- Implement progressive delays and account lockout after repeated failures

## API5:2023 — Broken Function Level Authorization

### Description
Complex access control with different roles and hierarchies leads to overlooked
authorization checks on specific functions. Attackers discover and call administrative
or privileged operations that are accessible but not intended for regular users.

### Attack Techniques
- Vertical privilege escalation: access /admin/, /internal/, /management/,
  /backoffice/, /superuser/ endpoints as a regular authenticated user
- HTTP method switching: try PUT, DELETE, PATCH on endpoints that the spec lists
  only for GET — hidden implementations may exist
- Admin endpoint discovery: test common admin path patterns even if not documented:
  /api/v1/admin, /api/admin, /admin/api/v1/users, /api/v1/users/admin
- Role parameter injection: add role=admin, is_admin=true to request body or query
- Privilege header injection: X-Role: admin, X-User-Type: administrator

### Example Payloads
GET /api/v1/admin/users (as a regular authenticated user)
DELETE /api/v1/users/123 (method not advertised in spec)
POST /api/v1/users with {"role": "admin", "username": "attacker"}
GET /api/v1/settings/all (undocumented admin endpoint)

### Detection Indicators
- HTTP 200 for an /admin/ endpoint as a non-admin user
- Administrative operations succeed (user created, data deleted) for regular user
- Role or privilege parameter accepted and reflected back in the response
- HTTP 200 instead of 405 for undocumented HTTP methods on existing paths

### Remediation
- Enforce function-level authorization on all endpoints; default-deny everything
- Explicitly define and enforce which roles may call each endpoint
- Disable HTTP methods not in use; return 405 Method Not Allowed for unused ones
- Do not rely on obscurity; assume adversaries will discover admin endpoints
- Separate admin API surface from the user-facing API (different base path or service)

## API6:2023 — Unrestricted Access to Sensitive Business Flows

### Description
Some API endpoints implement business processes that can be abused at scale without
appropriate controls. Mass assignment (binding all user-supplied parameters to internal
objects) is a specific sub-case that allows privilege escalation via submitted fields.

### Attack Techniques
- Mass assignment: inject unexpected fields in POST/PUT/PATCH request bodies. Target
  fields: role, isAdmin, admin, is_admin, permissions, user_id, userId, price,
  discount, balance, verified, active, status, privileged, superuser, trusted
- Business logic bypass: set price=0.01, quantity=-1, or discount=100 in order payloads
- Privilege escalation via registration: include role=admin or verified=true in
  account creation payload
- Parameter pollution: append extra fields alongside legitimate ones in all requests

### Example Payloads
POST /api/v1/register with: {"username":"x","password":"y","role":"admin","verified":true}
PUT /api/v1/profile with: {"name":"x","isAdmin":true,"balance":99999,"permissions":["all"]}
POST /api/v1/orders with: {"item_id":1,"quantity":1,"price":0.001,"discount":100}
PATCH /api/v1/users/me with: {"email":"x@y.com","is_admin":true}

### Detection Indicators
- Injected privileged field (role, isAdmin, admin) appears in the response body
- The injected field value persists in subsequent GET requests (mass assignment confirmed)
- HTTP status changes from 4xx to 2xx after adding the privileged field
- Balance, role, or privilege level changes after the request

### Remediation
- Use a strict allowlist of accepted fields for every endpoint; reject unknown properties
- Never use mass-assignment ORM features without explicit field filtering
- Implement server-side business logic validation; never trust client-submitted prices
- Separate user-modifiable fields from system-managed fields in the data model

## API7:2023 — Server Side Request Forgery (SSRF)

### Description
SSRF occurs when an API endpoint fetches a remote resource based on a URL or hostname
supplied by the client without validating the destination. Attackers force the server
to make requests to internal services, cloud metadata endpoints, or other restricted
destinations not accessible from the internet.

### Attack Techniques
- Cloud metadata access: inject cloud IMDS endpoints as the target URL
  AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
- Internal network probing: http://localhost:6379/ (Redis), http://127.0.0.1:8080/,
  http://10.0.0.1/, http://192.168.1.1/
- URL scheme abuse: file:///etc/passwd, dict://localhost:6379/info, gopher://
- DNS rebinding via attacker-controlled domains that resolve to internal IPs

### Example Payloads
POST /api/v1/fetch with: {"url": "http://169.254.169.254/latest/meta-data/"}
POST /api/v1/webhook with: {"callback_url": "http://localhost:6379/INFO"}
POST /api/v1/import with: {"source": "file:///etc/passwd"}
Any URL field: http://127.0.0.1/, http://[::1]/, http://0.0.0.0/

### Detection Indicators
- Response body contains AWS/GCP/Azure metadata content or IAM credentials
- Response time significantly longer for internal/loopback addresses
- Error messages reveal internal hostnames, IP addresses, or service names
- Response contains Redis INFO output, internal HTTP service responses

### Remediation
- Validate all user-supplied URLs: parse and check host against an allowlist
- Block all requests to private IP ranges (RFC 1918), loopback, and link-local
- Disable unnecessary URL schemes; only permit https:// (and http:// if required)
- Use a dedicated HTTP client with a restrictive outbound network policy
- Never resolve user-supplied hostnames on the server; use a proxy with controls

## API8:2023 — Security Misconfiguration

### Description
Security misconfiguration is the broadest vulnerability category. It includes injection
vulnerabilities (SQL, NoSQL, SSTI, XSS), verbose error messages, permissive CORS,
missing security headers, default credentials, and unnecessary feature exposure.

### Injection Attack Techniques
- SQL injection: ' OR '1'='1, '; DROP TABLE users;--, 1 OR 1=1, admin'--,
  ' UNION SELECT 1,2,3--, 1; WAITFOR DELAY '0:0:5'--
- NoSQL injection: {"$gt": ""}, {"$where": "1==1"}, {"$ne": null},
  {"$regex": ".*"}, {"$exists": true}
- SSTI detection: {{7*7}} (Jinja2/Twig), ${7*7} (Freemarker/Thymeleaf),
  <%= 7*7 %> (ERB), {{config}} (Flask), #{7*7} (Ruby), *{7*7} (Spring)
  Confirmed when response contains 49
- XSS via API: <script>alert(1)</script>, "><img src=x onerror=alert(1)>,
  javascript:alert(1), <svg onload=alert(1)>
- XXE: inject XML entity declarations in XML request bodies
- Command injection: ; id, | whoami, `id`, $(id), ; sleep 5

### CORS and Header Misconfiguration
- Test: add Origin: https://evil.com header; check if ACAO reflects it
- Missing headers: X-Content-Type-Options, Strict-Transport-Security,
  X-Frame-Options, Content-Security-Policy

### Detection Indicators
- SQL error in response: ORA-, You have an error in your SQL syntax, PG:, pg_
- SSTI confirmed: response contains 49 after {{7*7}} payload
- XSS: payload reflected in response body without HTML encoding
- CORS: Access-Control-Allow-Origin: * or mirrors attacker origin with credentials
- Verbose error: stack traces, file paths, or internal IP in 500 responses
- Default credentials accepted

### Remediation
- Use parameterized queries and prepared statements; never concatenate input into SQL
- Apply context-aware output encoding for all user-supplied data in responses
- Configure strict CORS policies with specific trusted origins
- Return generic error messages in production; log detailed errors server-side
- Disable HTTP methods not in use; return 405 for unsupported methods
- Remove version disclosure from Server and X-Powered-By headers

## API9:2023 — Improper Inventory Management

### Description
Organizations fail to maintain accurate inventories of their APIs, leaving old
versions, debug endpoints, and undocumented paths accessible. Attackers discover
these forgotten endpoints which often lack the security controls of current versions.

### Attack Techniques
- Version enumeration: test /api/v1/, /api/v2/, /api/v3/, /v1/, /v2/, /v3/, /api/
- API documentation discovery: GET /swagger.json, /openapi.yaml, /openapi.json,
  /api-docs, /swagger-ui.html, /v2/api-docs, /.well-known/openapi.json
- Debug endpoint discovery: /actuator, /actuator/env, /actuator/health,
  /debug, /trace, /api/debug, /internal/
- Environment leakage: test dev/staging paths from production contexts

### Example Payloads
GET /api/v1/users (when current API is /api/v2/users)
GET /swagger.json, GET /openapi.yaml (unauthenticated)
GET /actuator/env (Spring Boot actuator exposure)
GET /api/v0/admin (legacy version)

### Detection Indicators
- Old API versions return HTTP 200 and real data
- Swagger or OpenAPI spec accessible without authentication
- Debug or actuator endpoints return environment variables or configuration
- Deprecated endpoints still accept and process requests

### Remediation
- Maintain an up-to-date API inventory covering all versions and environments
- Retire old API versions with proper deprecation periods and sunset headers
- Protect API documentation endpoints behind authentication
- Use API gateways to enforce version lifecycle policies
- Regularly scan all environments for exposed documentation endpoints

## API10:2023 — Unsafe Consumption of APIs

### Description
When building integrations, developers tend to trust third-party APIs unconditionally,
applying weaker security standards. Attackers can compromise a third-party service
or manipulate its responses to inject malicious data into the target system.

### Attack Techniques
- Third-party data injection: if the API consumes and processes external data, that
  data may contain SQL injection, XSS, or SSTI payloads that execute in the target
- Malicious webhook responses: register as a third-party provider to send crafted
  responses containing injection payloads or oversized data
- OAuth redirect manipulation: tamper with OAuth callback URLs to redirect tokens
- Unsafe deserialization via third-party data: YAML/pickle/XML from external sources

### Example Attack Scenarios
A weather API returns city names; if unsanitized in SQL: inject SQL in city field
An OAuth provider returns user profile; if embedded in HTML without escaping: XSS
A payment webhook sends order status; if deserialized unsafely: RCE

### Detection Indicators
- Application processes and stores third-party API data without validation
- Error messages contain raw data from external API responses
- Third-party redirect or callback URLs not validated against allowlist
- Application trusts third-party data for authentication or authorization decisions

### Remediation
- Treat all third-party API responses as untrusted user input
- Validate and sanitize all data received from external APIs before processing
- Use strict allowlists for OAuth redirect URIs and webhook callback URLs
- Implement timeouts and circuit breakers for all third-party dependencies
- Audit third-party API contracts and monitor for unexpected response changes
