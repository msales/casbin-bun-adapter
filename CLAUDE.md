@~/CLAUDE.md

## Project Description

**Language:** Go 1.18  
**Module:** `github.com/msales/casbin-bun-adapter`  
**Purpose:** A Casbin adapter for the Bun ORM that stores authorization policy rules in PostgreSQL. Implements the full Casbin persist interface including filtered policies, batch operations, and auto-save updates.  
**Key dependencies:**
- `github.com/casbin/casbin/v2` -- authorization library
- `github.com/uptrace/bun` -- SQL-first Go ORM (with pgdialect, pgdriver, bundebug)
- `github.com/stretchr/testify` -- test assertions and suites
- `github.com/mmcloughlin/meow` -- hash function (indirect usage)

## Directory Structure

```
examples/           RBAC model and policy CSV files used in tests
.github/workflows/  GitHub Actions CI (test.yml)
```

Root-level files: `adapter.go` (main implementation + CasbinRule model), test files (`adapter_suite_test.go`, `adapter_policy_test.go`, `adapter_grouping_test.go`, `adapter_casbin_rule_test.go`).

## Build, Test & Lint

```bash
# Build
go build ./...

# Run tests (requires PostgreSQL -- use docker-compose)
docker-compose up -d postgres
go test ./...

# Run tests with verbose output
go test -v ./...

# Vet
go vet ./...

# Static analysis (CI uses staticcheck)
staticcheck ./...
```

Tests require a running PostgreSQL instance (see `docker-compose.yml`). CI runs on self-hosted runners with a PostgreSQL service container. Staticcheck is enabled in CI with ignores: `ST1000,SA1019,ST1003`.

## Code Style

### Imports

Three groups: stdlib, external, internal (separated by blank lines).

### Naming Conventions

- **Packages:** single lowercase word (`bunadapter`)
- **Interfaces:** Casbin-standard interface names (`persist.Adapter`, `persist.FilteredAdapter`)
- **Exported/unexported:** exported types for public API (`Adapter`, `CasbinRule`, `Filter`); unexported helpers (`save`, `delete`, `buildQuery`, `extractRules`)

### Error Handling

Errors are wrapped with `fmt.Errorf("context: %w", err)`. Transaction rollbacks on failure. Methods return `error` as last value.

### Testing

- Uses `testify/suite` (`AdapterTestSuite`) for integration tests
- Tests run against a real PostgreSQL database
- Suite handles DB setup/teardown and pre-population from fixture files
- Helper methods: `assertEnforcerPolicy`, `assertAllowed`, `assertDisallowed`

## Branching & Git

- **Never** work directly on `main` or `master`. Always create a new branch off the latest `main`/`master`.
- Before creating a branch, **always pull** the latest changes from the remote (`git pull origin main`).
- If the user provides a task identifier in the format `TRK-XXXX`, use it as the branch name (e.g., `TRK-1234`). Otherwise, **ask the user** for a task ID or branch name before proceeding.
- **Never push** to `main` or `master` directly.
- Commit changes after each meaningful iteration. Use your judgment to decide when progress should be saved -- prefer smaller, atomic commits over large monolithic ones.
- Write clear, concise commit messages. Use conventional commit format when appropriate (e.g., `feat:`, `fix:`, `refactor:`, `test:`).
