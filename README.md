# oidc-mock

[![CI](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml/badge.svg)](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/rophy/dbb4822dbc5782d5563947adde3358d3/raw/oidc-mock-coverage.json)](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml)

Mock OIDC provider for local development. Authorization Code flow with a user picker UI, JWT access tokens, and no external dependencies.

## Quick Start

```console
$ docker run --rm -p 8080:8080 ghcr.io/rophy/oidc-mock serve
```

Discovery: `http://localhost:8080/.well-known/openid-configuration`

Default config ships one confidential client (`default` / `secret`, redirect URI `http://localhost:8080/callback`) and two users (`user1` Alice with `roles: [admin]`, `user2` Bob with `roles: [viewer]`). Thanks to [loopback port flexibility](#notes), the default client also accepts `http://localhost:<any-port>/callback`. Override with your own config — see [Configuration](#configuration).

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | Discovery document |
| `/authorize` | GET/POST | Authorization (user picker UI) |
| `/token` | POST | Token exchange and refresh |
| `/userinfo` | GET/POST | User claims (Bearer header or `access_token` form POST) |
| `/jwks` | GET | JSON Web Key Set |
| `/revoke` | POST | Token revocation (RFC 7009, requires `client_id` + secret for confidential clients) |
| `/end-session` | GET/POST | RP-Initiated Logout (validates redirect, does not revoke tokens; returns `200 logged out` if no redirect URI) |

## Configuration

Provide config using exactly one of:

- `OIDC_CONFIG` env var — inline YAML
- `OIDC_CONFIG_FILE` env var — path to a YAML file
- `--config <file>` flag

Setting more than one is an error. `OIDC_PORT` overrides the port independently. Omitted top-level keys keep their defaults — e.g. setting only `clients` keeps the default users. Config is validated against a JSON schema; unknown keys are rejected at startup.

```yaml
# Full config example
port: 8080
issuer: http://localhost:8080
clients:
  - id: my-app
    secret: my-secret
    redirect_uris:
      - http://localhost:3000/callback
    post_logout_redirect_uris:        # optional; any URI matching a redirect_uri's scheme+host:port is always accepted
      - http://localhost:3000/logged-out
  - id: my-spa                        # public client (no secret)
    redirect_uris:
      - http://localhost:3000/callback
    allow_plain_code_challenge: true   # default: false (S256 required)
users:
  - sub: user1
    email: alice@example.com
    name: Alice
    password: secret123               # optional, prompts for password
    roles: [admin]                     # custom claim (any key beyond sub/email/name/password; overwrites generated claims of the same name)
  - sub: user2
    email: bob@example.com
    name: Bob
```

### Scopes

| Scope | Claims |
|-------|--------|
| `openid` | `sub` |
| `email` | `email`, `email_verified` |
| `profile` | `name` + custom claims |
| `offline_access` | enables refresh token |

### Client authentication

- **Confidential clients**: `client_secret_post` or `client_secret_basic` (credentials are URL-decoded per RFC 6749 §2.3.1)
- **Public clients**: omit `secret`. Must use PKCE with S256 (omitting `code_challenge_method` defaults to `plain`, which is rejected). Accepts Basic auth for `golang.org/x/oauth2` compatibility.
- **Confidential clients** may optionally use PKCE (S256 or plain) but it is not required.

### docker-compose

```yaml
services:
  oidc-mock:
    image: ghcr.io/rophy/oidc-mock:latest
    ports:
      - "8080:8080"
    command: serve
    environment:
      OIDC_CONFIG: |
        issuer: http://localhost:8080
        clients:
          - id: my-app
            secret: my-secret
            redirect_uris:
              - http://localhost:3000/callback
        users:
          - sub: user1
            email: alice@example.com
            name: Alice
```

Or mount a file: `OIDC_CONFIG_FILE: /config.yaml` with a volume.

## Notes

- **Issuer** must not contain a path (e.g. `http://localhost:8080`, not `http://localhost:8080/oidc`). Set it to the URL your clients actually use — in docker-compose, that's typically `http://localhost:<host-port>`, not the container-internal address.
- **All state is ephemeral.** Signing keys and tokens live in memory — a restart invalidates everything and rotates the JWKS. Resource servers that cache keys will need to refetch.
- **Access tokens** are signed JWTs (RFC 9068, `typ: at+jwt`) verifiable against `/jwks`. Claims: `iss`, `sub`, `aud` (= client_id), `scope`, `client_id`, `jti`, `exp`, `iat`. **ID tokens** carry: `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `at_hash`, `azp`, `auth_time`, plus `email`/`email_verified`/`name`/custom claims per scope. Both use string `aud` (not array) for single audiences.
- **Token lifetimes**: auth codes 60s, access/ID tokens 1h, refresh tokens don't expire. Each refresh issues a new refresh token without revoking the old one. Revocation via `/revoke` removes tokens from the store (revoking a refresh token also revokes **all** access tokens for that client+user pair) but JWT access tokens remain cryptographically valid until expiry.
- **Startup logs** print the full effective config including client secrets and user passwords.
- **Loopback redirects** allow any port (same scheme, host, and path) for `localhost`, `127.0.0.1`, and `[::1]` per RFC 8252 §7.3 — useful for CLI tools that bind an ephemeral port.
- **`response_mode=form_post`** is supported for ASP.NET Core and other clients that default to it.
- **`prompt=none`** always returns `login_required` (no server-side session). Use `offline_access` scope with refresh tokens for token renewal.
- **CORS** headers are set on all endpoints (`Access-Control-Allow-Origin: *`) for SPA compatibility.

## Building from source

```bash
go run . serve
go run . serve --config config.yaml
go run . help
```

Image published to `ghcr.io/rophy/oidc-mock`, tagged `latest` and `yyyymmdd-<hash>` on each push to master.
