# Architecture

## Overview
A Casbin policy storage adapter that persists authorization rules in PostgreSQL using the Bun ORM. It implements the full Casbin adapter interface including filtered policy loading, batch operations, and policy updates.

## Package Structure
- `bunadapter` (root) -- single package containing the adapter implementation and the CasbinRule model

## Key Interfaces
- `persist.Adapter` -- Casbin's core adapter interface (LoadPolicy, SavePolicy, AddPolicy, RemovePolicy, RemoveFilteredPolicy)
- `persist.FilteredAdapter` -- extended interface for filtered policy loading (LoadFilteredPolicy, IsFiltered)
- `persist.UpdatableAdapter` -- update interface (UpdatePolicy, UpdatePolicies, UpdateFilteredPolicies)
- `Filter` -- custom filter struct with P and G slices for filtering policy and grouping rules

## Data Flow
1. Casbin enforcer calls adapter methods (LoadPolicy, SavePolicy, etc.)
2. Adapter translates Casbin model rules into CasbinRule structs
3. CasbinRule structs are persisted to/loaded from `casbin.casbin_rules` PostgreSQL table via Bun ORM
4. Transactions are used for batch operations (save with truncate, update, delete)
5. Conflict resolution via `ON CONFLICT DO NOTHING` for inserts

## External Dependencies
- PostgreSQL 15.1+ (required for all operations)
- Table `casbin.casbin_rules` with schema created by test setup (`CREATE SCHEMA IF NOT EXISTS casbin`)
