# oidc-mock Roadmap

Compatibility gaps identified by auditing against OIDC Core 1.0, OAuth 2.0 (RFC 6749), RFC 7519 (JWT), and common provider behavior (Google, Auth0, Keycloak).

## High Priority

### CORS Support
Browser-based OIDC clients (`oidc-client-ts`, `@auth0/auth0-spa-js`, etc.) are completely blocked without CORS headers. All major providers support CORS on token, userinfo, JWKS, and discovery endpoints.

- Add `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers` to relevant endpoints
- Support preflight (`OPTIONS`) requests
- Make allowed origins configurable (default `*` for a mock)

### Redirect-based Authorization Errors
RFC 6749 §4.1.2.1: when `redirect_uri` and `client_id` are valid, errors must be returned as query params on the redirect URI (`?error=...&error_description=...`), not rendered as plain text on the authorization page. Client libraries expecting a redirect-with-error will hang with the current behavior.

- Return errors via redirect when redirect_uri is valid
- Keep direct error display only for invalid/unknown client_id or redirect_uri

## Medium Priority

### Add `azp` Claim to ID Token
OIDC Core §2: `azp` (authorized party) SHOULD be present when the audience contains the client. Google always includes it. Some client libraries (Google's own, Firebase) check for `azp` and may reject tokens without it.

- Set `azp` to the `client_id` that requested the token

### Add `auth_time` Claim to ID Token
OIDC Core §2: `auth_time` is REQUIRED when `max_age` is requested, OPTIONAL otherwise but recommended. Google, Auth0, and Keycloak all include it. Clients checking session freshness (e.g. `oidc-client-ts`) will log warnings or fail.

- Set `auth_time` to the time the user clicked the login button

## Low Priority

### Add `Pragma: no-cache` to Token Response
RFC 6749 §5.1 requires both `Cache-Control: no-store` and `Pragma: no-cache`. We only set the former. Spec validators will flag it.

### Add Charset to `Content-Type` Headers
Spec says `application/json;charset=UTF-8` on token and userinfo responses. We send `application/json`. Very few clients care, but it's a trivial fix.

## Done

- [x] Single-element `aud` serialized as string (b416c9b) — RFC 7519 §4.1.3
- [x] `at_hash` computed correctly
- [x] Token endpoint error responses use `{"error": "...", "error_description": "..."}` format
- [x] Comprehensive discovery document with all standard endpoints
- [x] Userinfo supports GET and POST with proper `WWW-Authenticate` errors
- [x] PKCE support for public clients
