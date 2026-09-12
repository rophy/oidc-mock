# oidc-mock

[![CI](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml/badge.svg)](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/rophy/dbb4822dbc5782d5563947adde3358d3/raw/oidc-mock-coverage.json)](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml)

Mock OIDC provider for local development. Implements the Authorization Code flow with a user picker UI and optional password protection per user.

**Supported features:** public and confidential clients, PKCE (S256 required by default, plain opt-in), optional per-user passwords, refresh tokens (`offline_access` scope), scope-based claim filtering, token revocation (RFC 7009), RP-Initiated Logout with validated `post_logout_redirect_uris`, `prompt=none` support, `at_hash`/`azp`/`auth_time`/`email_verified` claims, `client_secret_basic` auth, CORS (browser/SPA compatible).

## Getting Started

```console
$ docker run --rm -p 8080:8080 ghcr.io/rophy/oidc-mock serve
Runtime OIDC_CONFIG:
---
port: 8080
issuer: http://localhost:8080
clients:
    - id: default
      secret: secret
      redirect_uris:
        - http://localhost:8080/callback
users:
    - sub: user1
      email: alice@example.com
      name: Alice
      roles:
        - admin
    - sub: user2
      email: bob@example.com
      name: Bob
      roles:
        - viewer
---
oidc-mock listening on :8080
```

Discovery doc at `http://localhost:8080/.well-known/openid-configuration`.

## Configuration

Override defaults (see Getting Started) using exactly one of:

- `OIDC_CONFIG` env var — inline YAML
- `OIDC_CONFIG_FILE` env var — path to a YAML file
- `--config <file>` flag

Setting more than one is an error. `OIDC_PORT` overrides the port independently.

Any key in a user object beyond `sub`, `email`, `name`, and `password` becomes a custom claim in the ID token and `/userinfo` response (requires `profile` scope).

Users with a `password` field require password entry after selection. Users without it log in with a single click.

### Scopes

| Scope | Claims returned |
|-------|----------------|
| `openid` | `sub` |
| `email` | `email`, `email_verified` |
| `profile` | `name` + custom claims |
| `offline_access` | enables refresh token |

### Public clients

Omit `secret` from a client to make it a public client. Public clients must use PKCE with S256.

### PKCE

Pass `code_challenge` and `code_challenge_method` in the authorize request, then `code_verifier` in the token request. Public clients must use `S256` (the default). To allow `plain` for a public client, set `allow_plain_code_challenge: true` on the client:

```yaml
clients:
  - id: my-spa
    redirect_uris:
      - http://localhost:3000/callback
    allow_plain_code_challenge: true
```

### RP-Initiated Logout

The `/end-session` endpoint validates `post_logout_redirect_uri` against registered URIs. If not explicitly configured, it falls back to matching the origin (scheme + host) of the client's `redirect_uris`.

```yaml
clients:
  - id: my-app
    secret: my-secret
    redirect_uris:
      - http://localhost:3000/callback
    post_logout_redirect_uris:
      - http://localhost:3000/logged-out
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | Discovery document |
| `/authorize` | GET/POST | Authorization (shows user picker) |
| `/token` | POST | Token exchange and refresh (`client_secret_post` or `client_secret_basic`) |
| `/userinfo` | GET/POST | User claims (Bearer token or form-encoded) |
| `/jwks` | GET | JSON Web Key Set |
| `/revoke` | POST | Token revocation (RFC 7009, requires client auth) |
| `/end-session` | GET/POST | RP-Initiated Logout |

### docker-compose with inline config

```yaml
services:
  oidc-mock:
    image: ghcr.io/rophy/oidc-mock:latest
    ports:
      - "8080:8080"
    command: serve
    environment:
      OIDC_CONFIG: |
        clients:
          - id: my-app
            secret: my-secret
            redirect_uris:
              - http://localhost:3000/callback
        users:
          - sub: user1
            email: alice@example.com
            name: Alice
            roles: [admin]
```

### docker-compose with config file

```yaml
services:
  oidc-mock:
    image: ghcr.io/rophy/oidc-mock:latest
    ports:
      - "8080:8080"
    command: serve
    volumes:
      - ./config.yaml:/config.yaml
    environment:
      OIDC_CONFIG_FILE: /config.yaml
```

## Building from source

```bash
go run . serve
go run . serve --config config.yaml
go run . help
```

Image published to `ghcr.io/rophy/oidc-mock`, tagged `latest` and `yyyymmdd-<hash>` on each push to master.
