package bunadapter_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/stretchr/testify/suite"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"

	bunadapter "github.com/msales/casbin-bun-adapter"
)

// AdapterTestSuite tests all functionalities of Adapter
type AdapterTestSuite struct {
	suite.Suite
	conn string
	db   *bun.DB

	enforcer *casbin.Enforcer
	adapter  *bunadapter.Adapter
}

func TestAdapterTestSuite(t *testing.T) {
	suite.Run(t, new(AdapterTestSuite))
}

func (suite *AdapterTestSuite) SetupSuite() {
	suite.conn = "postgresql://user:pass@localhost:5432/test?sslmode=disable"

	db := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(suite.conn)))
	suite.db = bun.NewDB(db, pgdialect.New())
	suite.db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))

	err := suite.migrateDB()
	suite.Require().NoError(err)
}

func (suite *AdapterTestSuite) SetupTest() {
	var err error
	suite.adapter, err = bunadapter.NewAdapter(suite.db)
	suite.Require().NoError(err)

	suite.prePopulateUsingPoliciesFromFile()

	suite.enforcer, err = casbin.NewEnforcer("examples/rbac_model.conf", suite.adapter)
	suite.Require().NoError(err)
}

func (suite *AdapterTestSuite) prePopulateUsingPoliciesFromFile() {
	var err error
	// This is adapter trick to save the current policy to the DB.
	// We can't call temporaryFileEnforcer.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	temporaryFileEnforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)
	err = suite.adapter.SavePolicy(temporaryFileEnforcer.GetModel()) // this truncates the table, clearing out old data
	suite.Require().NoError(err)
}

func (suite *AdapterTestSuite) migrateDB() error {
	_, err := suite.db.NewCreateTable().Model((*bunadapter.CasbinRule)(nil)).IfNotExists().Exec(context.Background())
	if err != nil {
		return fmt.Errorf("failed to create casbin rules table: %w", err)
	}

	return nil
}

func (suite *AdapterTestSuite) assertEnforcerPolicy(res [][]string) {
	suite.T().Helper()
	expected := suite.enforcer.GetPolicy()
	suite.Assert().True(util.Array2DEquals(expected, res), "Policy Got: %v, supposed to be %v", res, expected)
}

func (suite *AdapterTestSuite) assertEnforcerGroupingPolicy(res [][]string) {
	suite.T().Helper()
	expected := suite.enforcer.GetGroupingPolicy()
	suite.Assert().True(util.Array2DEquals(expected, res), "Grouping Policy Got: %v, supposed to be %v", res, expected)
}

func (suite *AdapterTestSuite) assertAllowed(rvals ...interface{}) {
	suite.T().Helper()
	ok, err := suite.enforcer.Enforce(rvals...)
	suite.NoError(err)
	suite.True(ok)
}

func (suite *AdapterTestSuite) assertDisallowed(rvals ...interface{}) {
	suite.T().Helper()
	ok, err := suite.enforcer.Enforce(rvals...)
	suite.NoError(err)
	suite.False(ok)
}
