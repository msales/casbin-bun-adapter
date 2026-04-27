# Concerns & Risks

## Technical Debt
- CasbinRule ID is a random MD5 hash not derived from rule content -- code comments acknowledge this may cause rule duplication and suggest the PK should span all fields instead. Kept for backward DB schema compatibility.
- `context.Background()` is hardcoded in all database operations; no context propagation from callers.
- The global `rnd` random source initialized via `init()` with `time.Now().UnixNano()` is deprecated in newer Go versions.
- `UpdateFilteredPolicies` has a complex transaction that deletes and re-inserts rather than updating in place.

## Missing Coverage
- No unit tests (all tests are integration tests requiring PostgreSQL)
- No benchmark tests
- No tests for error paths (database failures, invalid inputs)
- No test for `Close()` method

## Security
- Database connection string is hardcoded in test suite (`postgresql://user:pass@postgres:5432/test`)
- Docker-compose uses `POSTGRES_HOST_AUTH_METHOD=trust`
- `ON CONFLICT DO NOTHING` silently drops duplicate inserts which could mask data integrity issues

## Performance
- Each policy rule insert is done individually within a transaction loop rather than using bulk insert
- `LoadPolicy` loads all rules into memory at once (no pagination)
- No connection pooling configuration exposed
- Lock-free random ID generation could cause collisions under high concurrency (though `ON CONFLICT DO NOTHING` mitigates this)
