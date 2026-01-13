# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI/CD pipeline with GitHub Actions
- Multi-architecture Docker image builds (amd64, arm64)
- Automated releases to GitHub Container Registry
- Version information embedded in binary
- Prometheus metrics middleware for request tracking
- Rate limiting middleware (10 req/s per IP, burst 20)
- Security headers middleware
- Separate metrics middleware for request duration, size, and count
- **Credential Synchronization**: Automatic credential updates when policies/roles change
- **Multi-Backend Support**: MinIO, AWS S3, and CEPH RadosGW integration
- **Role Cleanup**: Automatic removal of non-existent roles from credentials
- **Legacy Credential Handling**: Support for credentials created before backend configuration
- **Comprehensive Integration Tests**: Automated test suite with OIDC simulation
- **Test Suite Reorganization**: Moved tests to dedicated `test/` directory

### Changed
- Simplified architecture by removing nginx reverse proxy
- Frontend now served directly from Go application
- Updated to Go 1.25
- Improved Makefile with version management
- **Enhanced Credential Management**: Credentials now synchronize automatically with backend policies

### Fixed
- OIDC callback route handling
- Frontend API endpoint configuration
- **Backend Integration Issues**: Fixed MinIO, AWS, and CEPH client implementations
- **Policy Combination**: Improved policy merging for multi-role credentials

## [1.0.0] - Initial Release

### Added
- OIDC authentication with multiple provider support
- S3 proxy with AWS Signature V4 signing
- Policy-based access control
- Self-service credential management
- Web-based management UI
- Dual policy sources (built-in + user-created)
- Admin mode toggle
- S3 browser with upload/download/delete
- Secret key visibility toggle
- AWS CLI configuration export
- Health check endpoint
- Prometheus metrics endpoint
- Docker Compose deployment
- Comprehensive documentation

### Security
- Secure secret storage
- OIDC token validation
- Policy-based authorization
- Rate limiting
- Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- Audit logging

[Unreleased]: https://github.com/HarryKodden/S3-Gateway/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/HarryKodden/S3-Gateway/releases/tag/v1.0.0
