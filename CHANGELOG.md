# Changelog

All notable changes to the Website Security Scanner project will be documented in this file.
The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [2.0.0] - 2026-02-07
### Added
- Docker deployment assets (`Dockerfile`, `docker-compose.yml`, `.dockerignore`).
- Environment template (`.env.example`) for required configuration.
- Development and deployment guides (`DEVELOPMENT.md`, `DEPLOYMENT.md`).
- Expanded test suite with pytest configuration.

### Changed
- Packaging metadata updated to support thesis submission and development workflows.
- README updated with Docker quick start and documentation links.

### Fixed
- Web app now requires `SECRET_KEY` from environment or config for safer defaults.

## [1.0.0] - 2026-01-31
### Added
- Initial scanner release with CLI and platform analyzers.
- Web interface for interactive scans and reports.
