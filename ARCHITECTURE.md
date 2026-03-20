# Architecture: duo_universal_php

## Purpose

A PHP SDK for Duo Security's Universal Prompt (OAuth 2.0-based two-factor authentication). It handles the full MFA flow: generating the authorization URL, exchanging the authorization code for a token, and validating the returned JWT to confirm the user authenticated successfully.

## Directory Structure

```
src/
  Client.php          — Main SDK client: health check, auth URL generation, token exchange, JWT validation
  Duo_Exception.php   — Domain exception thrown on Duo API errors, invalid configuration, or JWT failures

example/
  index.php           — Minimal PHP login flow demonstrating the SDK (redirect → callback → success)
  templates/          — Login and success page templates

tests/
  Client_Test.php     — Unit tests covering the full auth flow with mocked HTTP responses
```

## Key Design Decisions

- **JWT-based token exchange** — uses `firebase/php-jwt` to sign the token request (`client_assertion`) and to decode/validate the returned `id_token` (HS512).
- **State parameter** — callers must generate a cryptographically random `state` string (22–1024 chars) and round-trip it through the auth flow to prevent CSRF.
- **Nonce binding** — a nonce is embedded in the JWT and validated after token exchange to prevent replay attacks.
- **Bundled Duo CA** — `ca_certs.pem` is shipped with the package so token-endpoint requests use Duo's known certificate chain, not the system bundle.
- **Health check** — `health_check()` hits `/oauth/v1/health_check` before initiating auth, allowing callers to degrade gracefully if Duo is unavailable.

## Extension Points

- Inject a custom HTTP client by subclassing or wrapping `Client` to override the HTTP call methods (useful for testing).
- Override `DUO_CERTS` path to supply a custom CA bundle.

## Dependency Flow

```
Login page
  └── Client::create_auth_url(username, state)
        └── redirects to Duo's /oauth/v1/authorize

Duo callback (with code + state)
  └── Client::exchange_authorization_code_for_2fa_result(duo_code, username, nonce, state)
        ├── POST /oauth/v1/token (signed with HS512 JWT)
        └── validate id_token JWT → return decoded user info
```
