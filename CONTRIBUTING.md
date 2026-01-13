# Contributing to S3 Gateway

Thank you for your interest in contributing to S3 Gateway!

## Development Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd S3-Gateway
```

2. Install Go 1.21+:
```bash
go version  # Should be 1.21 or higher
```

3. Install dependencies:
```bash
go mod download
```

4. Copy example configuration:
```bash
cp config.example.yaml config.yaml
```

5. Run tests:
```bash
make test
```

## Running Locally

```bash
# Run with default config
make run

# Or build and run
make build
./s3-gateway -config config.yaml
```

## Code Style

- Follow Go best practices
- Run `go fmt` before committing
- Use meaningful variable names
- Add comments for complex logic
- Write tests for new features

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package
go test -v ./internal/policy
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Add tests
5. Run tests: `make test`
6. Commit with clear messages
7. Push to your fork
8. Open a pull request

## Commit Messages

Use clear, descriptive commit messages:

```
feat: add support for S3 multipart uploads
fix: handle nil pointer in policy evaluation
docs: update deployment guide
test: add tests for OIDC authentication
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
