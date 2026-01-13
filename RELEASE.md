# Release Process

## Semantic Versioning

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version: Incompatible API changes
- **MINOR** version: Add functionality in a backward compatible manner
- **PATCH** version: Backward compatible bug fixes

## Creating a Release

### 1. Prepare the Release

1. Update `CHANGELOG.md` with the new version and changes
2. Ensure all tests pass: `make test`
3. Update documentation if needed

### 2. Create and Push a Tag

```bash
# For a new release (e.g., v1.2.3)
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3

# For a pre-release (alpha, beta, rc)
git tag -a v1.2.3-beta.1 -m "Beta release v1.2.3-beta.1"
git push origin v1.2.3-beta.1
```

### 3. Automated Process

When you push a tag, GitHub Actions will automatically:

1. **Run Tests**: Execute all unit tests
2. **Build Binaries**: Create binaries for multiple platforms:
   - Linux (amd64, arm64)
   - macOS (amd64, arm64)
   - Windows (amd64)
3. **Build Docker Images**: Multi-arch images (amd64, arm64)
4. **Push to Registry**: Push images to `ghcr.io/harrykodden/s3-gateway`
5. **Create GitHub Release**: With changelog and binary artifacts
6. **Security Scan**: Run Trivy vulnerability scanner

### 4. Docker Image Tags

The following tags are created:
- `v1.2.3` - Specific version
- `v1.2` - Minor version (latest patch)
- `v1` - Major version (latest minor)
- `latest` - Latest stable release (main branch)
- `main` - Latest commit on main branch
- `develop` - Latest commit on develop branch
- `main-abc1234` - Commit SHA prefix

## Manual Release (Local)

### Build and Test Locally

```bash
# Build with version info
make build

# Show version
./s3-gateway -version

# Build for all platforms
make build-all

# Run tests
make test
make test-coverage
```

### Build and Push Docker Image

```bash
# Build Docker image with version
VERSION=v1.2.3 make docker-build

# Push to registry
VERSION=v1.2.3 make docker-push

# Or do both
VERSION=v1.2.3 make docker-release
```

## Using Released Images

### Pull from GitHub Container Registry

```bash
# Pull latest
docker pull ghcr.io/harrykodden/s3-gateway:latest

# Pull specific version
docker pull ghcr.io/harrykodden/s3-gateway:v1.2.3

# Pull latest on specific major version
docker pull ghcr.io/harrykodden/s3-gateway:v1
```

### Update docker-compose.yml

```yaml
services:
  s3-gateway:
    image: ghcr.io/harrykodden/s3-gateway:v1.2.3
    # ... rest of config
```

## Version Information

The application embeds version information at build time:

```bash
# Show version
./s3-gateway -version

# Output:
# S3 Access Manager
# Version:    v1.2.3
# Commit:     abc1234
# Build Date: 2026-01-09T12:00:00Z
```

## Pre-releases

Tag format for pre-releases:
- `v1.2.3-alpha.1` - Alpha release
- `v1.2.3-beta.1` - Beta release
- `v1.2.3-rc.1` - Release candidate

Pre-releases are marked as such in GitHub Releases.

## Hotfix Releases

For urgent fixes on a released version:

1. Create a hotfix branch from the tag
   ```bash
   git checkout -b hotfix/v1.2.4 v1.2.3
   ```

2. Make the fix and commit
   ```bash
   git commit -am "Fix critical issue"
   ```

3. Tag and push
   ```bash
   git tag -a v1.2.4 -m "Hotfix v1.2.4"
   git push origin v1.2.4
   ```

## Rollback

To rollback to a previous version:

```bash
# Pull previous version
docker pull ghcr.io/harrykodden/s3-gateway:v1.2.2

# Update docker-compose.yml
# Change image tag to v1.2.2

# Restart
docker compose up -d
```
