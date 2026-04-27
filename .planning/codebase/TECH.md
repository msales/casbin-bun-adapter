# Technology Stack

## Language & Runtime
Go 1.18

## Dependencies
- `github.com/casbin/casbin/v2 v2.36.1` -- authorization library providing the adapter interface
- `github.com/uptrace/bun v1.1.5` -- SQL-first Go ORM for PostgreSQL
- `github.com/uptrace/bun/dialect/pgdialect v1.1.5` -- PostgreSQL dialect for Bun
- `github.com/uptrace/bun/driver/pgdriver v1.1.5` -- PostgreSQL driver for Bun
- `github.com/uptrace/bun/extra/bundebug v1.1.5` -- debug query hook (used in tests)
- `github.com/mmcloughlin/meow v0.0.0` -- meow hash (indirect)
- `github.com/stretchr/testify v1.7.0` -- test assertions and suite runner

## Build System
- No Makefile; build via `go build ./...`
- `Dockerfile` uses `msales/go-builder:1.20-base-1.0.2` for CI builds
- `docker-compose.yml` provides PostgreSQL 15.1 for local testing

## Testing
- `testify/suite` for integration test suites
- Tests require a live PostgreSQL instance (docker-compose or CI service)
- No unit-only tests; all tests are integration tests against the database

## CI/CD
- GitHub Actions workflow `.github/workflows/test.yml`
- Runs on self-hosted runners with PostgreSQL service container
- Executes: go test, go vet, staticcheck (with race detection and parallel mode)
