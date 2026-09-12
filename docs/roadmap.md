# oidc-mock Roadmap

Compatibility gaps identified by auditing against OIDC Core 1.0, OAuth 2.0 (RFC 6749), RFC 7519 (JWT), and common provider behavior (Google, Auth0, Keycloak).

## Done

- [x] Single-element `aud` serialized as string — RFC 7519 §4.1.3
- [x] `at_hash` computed correctly
- [x] Token endpoint error responses use `{"error": "...", "error_description": "..."}` format
- [x] Comprehensive discovery document with all standard endpoints
- [x] Userinfo supports GET and POST with proper `WWW-Authenticate` errors
- [x] PKCE support for public clients
- [x] CORS support — `Access-Control-Allow-Origin: *`, preflight `OPTIONS` handling
- [x] Redirect-based authorization errors — RFC 6749 §4.1.2.1 compliant error redirects
- [x] `azp` claim in ID token — set to `client_id` per OIDC Core §2
- [x] `auth_time` claim in ID token — set to authentication time per OIDC Core §2
- [x] `Pragma: no-cache` on token response — RFC 6749 §5.1
- [x] `Content-Type: application/json;charset=UTF-8` on token, userinfo, and error responses
