# oidc-mock

[![CI](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml/badge.svg)](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/rophy/dbb4822dbc5782d5563947adde3358d3/raw/oidc-mock-coverage.json)](https://github.com/rophy/oidc-mock/actions/workflows/ci.yaml)

Mock OIDC provider for local development. Implements the Authorization Code flow with a user picker UI and optional password protection per user.

**Supported features:** optional per-user passwords, PKCE (S256/plain), refresh tokens (`offline_access` scope), scope-based claim filtering, token revocation, RP-Initiated Logout, `at_hash`/`email_verified` claims.

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
| `email` | `email` |
| `profile` | `name` + custom claims |
| `offline_access` | enables refresh token |

### PKCE

Supported for public clients. Pass `code_challenge` and `code_challenge_method` (`S256` or `plain`) in the authorize request, then `code_verifier` in the token request.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | Discovery document |
| `/authorize` | GET | Authorization (shows user picker) |
| `/token` | POST | Token exchange and refresh |
| `/userinfo` | GET/POST | User claims (Bearer token or form-encoded) |
| `/jwks` | GET | JSON Web Key Set |
| `/revoke` | POST | Token revocation (RFC 7009) |
| `/end-session` | GET | RP-Initiated Logout |

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
```

Image published to `ghcr.io/rophy/oidc-mock`, tagged `latest` and `yyyymmdd-<hash>` on each push to master.
