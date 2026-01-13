---
name: Release Checklist
about: Checklist for creating a new release
title: 'Release v[VERSION]'
labels: release
assignees: ''
---

## Release Checklist

Version: `v[VERSION]`

### Pre-release
- [ ] All tests passing on main branch
- [ ] Update CHANGELOG.md with new version and changes
- [ ] Update version in documentation if needed
- [ ] Review and merge all pending PRs for this release
- [ ] Verify Docker images build successfully locally

### Release
- [ ] Create and push git tag: `git tag -a v[VERSION] -m "Release v[VERSION]"`
- [ ] Verify GitHub Actions workflow completes successfully
- [ ] Verify Docker images are pushed to ghcr.io
- [ ] Verify binaries are attached to GitHub release
- [ ] Test Docker image: `docker pull ghcr.io/harrykodden/s3-gateway:v[VERSION]`

### Post-release
- [ ] Announce release (if applicable)
- [ ] Update documentation site (if applicable)
- [ ] Close related milestone
- [ ] Create next milestone

### Rollback Plan
If issues are discovered after release:
1. Document the issue
2. Revert to previous version: `ghcr.io/harrykodden/s3-gateway:v[PREVIOUS_VERSION]`
3. Create hotfix branch if needed
4. Release patch version

### Notes
<!-- Add any additional notes about this release -->
