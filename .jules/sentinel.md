## 2024-12-24 - Username Enumeration via Timing
**Vulnerability:** The login process returned immediately if a username was not found, but performed an expensive `bcrypt` comparison if it was found. This timing discrepancy allowed attackers to enumerate valid usernames.
**Learning:** Returning early on "user not found" when using slow hash functions (like bcrypt/argon2) leaks existence information via side-channel (time).
**Prevention:** Always perform a hash comparison, even if the user is not found. Use a pre-calculated dummy hash (of the same cost) to ensure the timing is indistinguishable from a valid user with an incorrect password.
## 2024-12-24 - CSRF Protection Missing
**Vulnerability:** The application lacks CSRF protection for form submissions, making it vulnerable to cross-site request forgery attacks.
**Learning:** Standard form-based authentication often requires explicit CSRF token management, unlike modern API-centric SPAs which might rely on other mechanisms or frameworks that handle it.
**Prevention:** Implement CSRF middleware that validates tokens on state-changing requests (POST, PUT, DELETE).

## 2024-12-24 - Session Cookie Encryption
**Vulnerability:** The session cookie was signed but not encrypted. This exposed the user's `masterKey` (used for password decryption) in the cookie value, allowing anyone with access to the cookie (e.g., via network interception if HTTP is used, or local inspection) to obtain the key.
**Learning:** `gorilla/sessions` `NewCookieStore` treats the first key as the signing key and subsequent keys as encryption keys. Providing only one key enables signing only.
**Prevention:** Always provide both authentication and encryption keys when initializing a cookie store if the session contains sensitive data.

## 2024-12-24 - Unchecked Random Read
**Vulnerability:** The `generateRandomToken` function ignored errors from `rand.Read`, which could lead to non-random tokens if the CSPRNG fails.
**Learning:** `crypto/rand` can fail, and silently ignoring the error can result in zeroed buffers being used as security tokens.
**Prevention:** Always check errors from `rand.Read`. If randomness is critical for security and cannot be guaranteed, the application should fail securely (panic).

## 2026-01-09 - Missing Re-Authentication on Password Change
**Vulnerability:** The "Change Password" functionality did not require the user's current password. This allowed an attacker with session access (e.g., via hijacked cookie or unlocked workstation) to change the password and take over the account.
**Learning:** Sensitive actions, especially those affecting authentication credentials, must always require re-authentication (Knowledge Factor) to prevent account takeover from session compromise.
**Prevention:** Enforce current password verification for all password change or account recovery operations.
