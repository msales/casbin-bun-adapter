# casbin-bun-adapter

[Bun](https://bun.uptrace.dev) adapter for [Casbin](https://github.com/casbin/casbin).


## Testing locally
https://msales.atlassian.net/wiki/spaces/TECH/pages/3061972993/Testing+Same+service+address+in+Github+actions+as+in+local


## Simple Example

```go
package main

import (
	"database/sql"

	bunadapter "github.com/msales/casbin-bun-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func main() {
	// Initialize a database connection (PostgreSQL in this example).
	dbDSN := "postgresql://username:password@postgres:5432/database?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dbDSN)))
	db := bun.NewDB(sqldb, pgdialect.New())
	
	// Initialize an adapter.
	// The adapter will use the Postgres database named "casbin" and a table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	a, _ := bunadapter.NewAdapter(db)

	// Use the adapter when creating a new instance of an enforcer.
	e := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// Load the policy from the DB.
	e.LoadPolicy()

	// Check the permission.
	e.Enforce("alice", "data1", "read")

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to the DB.
	e.SavePolicy()
}
```

## Support for FilteredAdapter interface

You can [load a subset of policies](https://casbin.org/docs/en/policy-subset-loading) with this adapter:

```go
package main

import (
	"github.com/casbin/casbin/v2"
	bunadapter "github.com/casbin/casbin-bun-adapter"
	"github.com/uptrace/bun"
)

func main() {
	db := bun.NewDB(...)
	a, _ := bunadapter.NewAdapter(db)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.LoadFilteredPolicy(&bunadapter.Filter{
		P: []string{"", "data1"},
		G: []string{"alice"},
	})
	...
}
```

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
