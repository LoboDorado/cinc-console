# Changelog

All notable changes to this project are documented in this file.

## 0.6.0 - 2026-08-12

### Added

- Added optional LDAP bind authentication (`AUTH_MODE=ldap`): a server-only
  search-then-bind client (`lib/ldap/client.ts`) verifies credentials against
  an external directory instead of the Cinc server's own password check. The
  authenticated username must already exist as a Cinc user object — LDAP
  never provisions one.
- Hid the "Change password" action on the profile page for LDAP-authenticated
  users, since their password is managed by the directory.

### Fixed

- Fixed a Next.js production-build crash (`Cannot read properties of
  undefined (reading 'toLowerCase')`) on every LDAP login attempt, caused by
  Turbopack bundling `ldapjs`'s raw TLS/BER handling; `ldapjs` is now opted
  out of bundling via `serverExternalPackages`.

### Helm / Deployment

- Added `authMode`/`ldap.*` values and ConfigMap/Secret wiring for LDAP bind
  authentication.
- Extended the NetworkPolicy egress rules to allow LDAP/LDAPS ports (389/636,
  plus `ldap.extraNetworkPolicyPorts` for non-standard ports) when
  `authMode: ldap`.

## 0.5.0 - 2026-07-28

### Added

- Added `.env.example` with documented runtime configuration defaults and placeholders.
- Added optional `CINC_AUTH_ACTOR` support for a globally privileged signing actor.
- Added `TROUBLESHOOTING.md` guidance for `403 missing create permission` login failures.

### Changed

- Improved login/session handling to stabilize auth cookie behavior in proxied and enterprise deployments.
- Expanded build/deployment docs for private npm mirrors and cross-platform image builds.

### Helm / Deployment

- Added and documented `authActor` chart support (`CINC_AUTH_ACTOR` env wiring).
- Added a NetworkPolicy template with explicit ingress/egress port rules.
- Updated default image tag in Helm values to `0.1.1`.

## 0.1.0

- Initial release of Cinc Console.
