## 2024-12-24 - CSRF Protection Missing
**Vulnerability:** The application lacks CSRF protection for form submissions, making it vulnerable to cross-site request forgery attacks.
**Learning:** Standard form-based authentication often requires explicit CSRF token management, unlike modern API-centric SPAs which might rely on other mechanisms or frameworks that handle it.
**Prevention:** Implement CSRF middleware that validates tokens on state-changing requests (POST, PUT, DELETE).

## 2024-12-24 - Session Cookie Encryption
**Vulnerability:** The session cookie was signed but not encrypted. This exposed the user's `masterKey` (used for password decryption) in the cookie value, allowing anyone with access to the cookie (e.g., via network interception if HTTP is used, or local inspection) to obtain the key.
**Learning:** `gorilla/sessions` `NewCookieStore` treats the first key as the signing key and subsequent keys as encryption keys. Providing only one key enables signing only.
**Prevention:** Always provide both authentication and encryption keys when initializing a cookie store if the session contains sensitive data.
