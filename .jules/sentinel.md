## 2024-12-24 - CSRF Protection Missing
**Vulnerability:** The application lacks CSRF protection for form submissions, making it vulnerable to cross-site request forgery attacks.
**Learning:** Standard form-based authentication often requires explicit CSRF token management, unlike modern API-centric SPAs which might rely on other mechanisms or frameworks that handle it.
**Prevention:** Implement CSRF middleware that validates tokens on state-changing requests (POST, PUT, DELETE).
