package bunadapter

import (
	"database/sql"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/stretchr/testify/suite"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
)

// AdapterTestSuite tests all functionalities of Adapter
type AdapterTestSuite struct {
	suite.Suite

	conn string
	db   *bun.DB
	e    *casbin.Enforcer
	a    *Adapter
}

func TestAdapterTestSuite(t *testing.T) {
	suite.Run(t, new(AdapterTestSuite))
}

func (suite *AdapterTestSuite) TestSaveLoad() {
	suite.Assert().False(suite.e.IsFiltered())
	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		suite.e.GetPolicy(),
	)
}

func (suite *AdapterTestSuite) TestAutoSave() {
	// AutoSave is enabled by default.
	// Now we disable it.
	suite.e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, err := suite.e.AddPolicy("alice", "data1", "write")
	suite.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)
	// This is still the original policy.
	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		suite.e.GetPolicy(),
	)

	// Now we enable the AutoSave.
	suite.e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, err = suite.e.AddPolicy("alice", "data1", "write")
	suite.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)
	// The policy has a new rule: {"alice", "data1", "write"}.
	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}},
		suite.e.GetPolicy(),
	)

	// Aditional AddPolicy have no effect
	_, err = suite.e.AddPolicy("alice", "data1", "write")
	suite.Require().NoError(err)
	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)
	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}},
		suite.e.GetPolicy(),
	)

	_, err = suite.e.AddPolicies([][]string{
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
		{"bob", "data1", "read"},
	})
	suite.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)
	// The policy has a new rule: {"alice", "data1", "write"}.
	suite.assertPolicy(
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
			{"alice", "data1", "write"},
			{"bob", "data2", "read"},
			{"alice", "data2", "write"},
			{"alice", "data2", "read"},
			{"bob", "data1", "write"},
			{"bob", "data1", "read"},
		},
		suite.e.GetPolicy(),
	)

	suite.Require().NoError(err)
}

func (suite *AdapterTestSuite) TestRemovePolicy() {
	_, err := suite.e.RemovePolicy("alice", "data1", "read")
	suite.Require().NoError(err)

	suite.assertPolicy(
		[][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		suite.e.GetPolicy(),
	)

	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertPolicy(
		[][]string{{"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		suite.e.GetPolicy(),
	)

	_, err = suite.e.RemovePolicies([][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
	suite.Require().NoError(err)

	suite.assertPolicy(
		[][]string{{"bob", "data2", "write"}},
		suite.e.GetPolicy(),
	)
}

func (suite *AdapterTestSuite) TestRemoveFilteredPolicy() {
	_, err := suite.e.RemoveFilteredPolicy(0, "", "data2")
	suite.Require().NoError(err)

	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}},
		suite.e.GetPolicy(),
	)

	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}},
		suite.e.GetPolicy(),
	)
}

func (suite *AdapterTestSuite) TestLoadFilteredPolicy() {
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", suite.a)
	suite.Require().NoError(err)

	err = e.LoadFilteredPolicy(&Filter{
		P: []string{"", "", "read"},
	})
	suite.Require().NoError(err)
	suite.Assert().True(e.IsFiltered())
	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"data2_admin", "data2", "read"}},
		e.GetPolicy(),
	)
}

func (suite *AdapterTestSuite) TestLoadFilteredGroupingPolicy() {
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", suite.a)
	suite.Require().NoError(err)

	err = e.LoadFilteredPolicy(&Filter{
		G: []string{"bob"},
	})
	suite.Require().NoError(err)
	suite.Assert().True(e.IsFiltered())
	suite.assertPolicy([][]string{}, e.GetGroupingPolicy())

	e, err = casbin.NewEnforcer("examples/rbac_model.conf", suite.a)
	suite.Require().NoError(err)

	err = e.LoadFilteredPolicy(&Filter{
		G: []string{"alice"},
	})
	suite.Require().NoError(err)
	suite.Assert().True(e.IsFiltered())
	suite.assertPolicy([][]string{{"alice", "data2_admin"}}, e.GetGroupingPolicy())
}

func (suite *AdapterTestSuite) TestLoadFilteredPolicyNilFilter() {
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", suite.a)
	suite.Require().NoError(err)

	err = e.LoadFilteredPolicy(nil)
	suite.Require().NoError(err)

	suite.Assert().False(e.IsFiltered())
	suite.assertPolicy(
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}},
		suite.e.GetPolicy(),
	)
}

func (suite *AdapterTestSuite) TestSavePolicyClearPreviousData() {
	suite.e.EnableAutoSave(false)
	policies := suite.e.GetPolicy()
	// clone slice to avoid shufling elements
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := suite.e.RemovePolicy(p)
		suite.Require().NoError(err)
	}
	policies = suite.e.GetGroupingPolicy()
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := suite.e.RemoveGroupingPolicy(p)
		suite.Require().NoError(err)
	}
	suite.assertPolicy(
		[][]string{},
		suite.e.GetPolicy(),
	)

	err := suite.e.SavePolicy()
	suite.Require().NoError(err)

	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)
	suite.assertPolicy(
		[][]string{},
		suite.e.GetPolicy(),
	)
}

func (suite *AdapterTestSuite) TestUpdatePolicy() {
	var err error
	suite.e, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)

	suite.e.SetAdapter(suite.a)

	err = suite.e.SavePolicy()
	suite.Require().NoError(err)

	_, err = suite.e.UpdatePolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}, [][]string{{"bob", "data1", "read"}, {"alice", "data2", "write"}})
	suite.Require().NoError(err)

	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertPolicy(suite.e.GetPolicy(), [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"bob", "data1", "read"}, {"alice", "data2", "write"}})
}

func (suite *AdapterTestSuite) TestUpdatePolicyWithLoadFilteredPolicy() {
	var err error
	suite.e, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)

	suite.e.SetAdapter(suite.a)

	err = suite.e.SavePolicy()
	suite.Require().NoError(err)

	err = suite.e.LoadFilteredPolicy(&Filter{P: []string{"data2_admin"}})
	suite.Require().NoError(err)

	_, err = suite.e.UpdatePolicies(suite.e.GetPolicy(), [][]string{{"bob", "data2", "read"}, {"alice", "data2", "write"}})
	suite.Require().NoError(err)

	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertPolicy(suite.e.GetPolicy(), [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"bob", "data2", "read"}, {"alice", "data2", "write"}})
}

func (suite *AdapterTestSuite) TestUpdateFilteredPolicies() {

	var err error
	suite.e, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)

	suite.e.SetAdapter(suite.a)

	err = suite.e.SavePolicy()
	suite.Require().NoError(err)

	_, err = suite.a.UpdateFilteredPolicies("p", "p", [][]string{{"alice", "data2", "write"}}, 0, "alice", "data1", "read")
	suite.Require().NoError(err)
	_, err = suite.a.UpdateFilteredPolicies("p", "p", [][]string{{"bob", "data1", "read"}}, 0, "bob", "data2", "write")
	suite.Require().NoError(err)

	err = suite.e.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertPolicy(suite.e.GetPolicy(), [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data2", "write"}, {"bob", "data1", "read"}})
}

func (suite *AdapterTestSuite) SetupSuite() {
	suite.conn = "postgresql://user:pass@localhost:5432/test?sslmode=disable"

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(suite.conn)))
	suite.db = bun.NewDB(sqldb, pgdialect.New())

	suite.db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
}

func (suite *AdapterTestSuite) SetupTest() {
	suite.dropCasbinDB()

	var err error
	suite.a, err = NewAdapter(suite.db)
	suite.Require().NoError(err)

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)
	err = suite.a.SavePolicy(e.GetModel())
	suite.Require().NoError(err)

	suite.e, err = casbin.NewEnforcer("examples/rbac_model.conf", suite.a)
	suite.Require().NoError(err)
}

func (suite *AdapterTestSuite) dropCasbinDB() {
	_, err := suite.db.Exec("DROP DATABASE IF EXISTS casbin")
	suite.Require().NoError(err)
}

func (suite *AdapterTestSuite) assertPolicy(expected, res [][]string) {
	suite.T().Helper()
	suite.Assert().True(util.Array2DEquals(expected, res), "Policy Got: %v, supposed to be %v", res, expected)
}
