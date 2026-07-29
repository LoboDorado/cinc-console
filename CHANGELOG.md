# Changelog

All notable changes to this project are documented in this file.

## 0.1.1 - 2026-07-28

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
