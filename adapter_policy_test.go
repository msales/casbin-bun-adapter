package bunadapter_test

import (
	"github.com/casbin/casbin/v2"

	bunadapter "github.com/msales/casbin-bun-adapter"
)

func (suite *AdapterTestSuite) TestSaveLoad() {
	suite.Assert().False(suite.enforcer.IsFiltered())
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
}

func (suite *AdapterTestSuite) TestAutoSave() {
	// AutoSave is enabled by default.
	// Now we disable it.
	suite.enforcer.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, err := suite.enforcer.AddPolicy("alice", "data1", "write")
	suite.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)
	// This is still the original policy.
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})

	// Now we enable the AutoSave.
	suite.enforcer.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, err = suite.enforcer.AddPolicy("alice", "data1", "write")
	suite.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)
	// The policy has adapter new rule: {"alice", "data1", "write"}.
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"alice", "data1", "write"},
	})

	// Additional AddPolicy have no effect
	_, err = suite.enforcer.AddPolicy("alice", "data1", "write")
	suite.Require().NoError(err)
	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"alice", "data1", "write"},
	})

	_, err = suite.enforcer.AddPolicies([][]string{
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
		{"bob", "data1", "read"},
	})
	suite.Require().NoError(err)
	// Reload the policy from the storage to see the effect.
	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)
	// The policy has adapter new rule: {"alice", "data1", "write"}.
	suite.assertEnforcerPolicy([][]string{
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
	})

	suite.Require().NoError(err)
}

func (suite *AdapterTestSuite) TestRemovePolicy() {
	_, err := suite.enforcer.RemovePolicy("alice", "data1", "read")
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})

	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})

	_, err = suite.enforcer.RemovePolicies([][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{{"bob", "data2", "write"}})
}

func (suite *AdapterTestSuite) TestRemoveFilteredPolicy() {
	_, err := suite.enforcer.RemoveFilteredPolicy(0, "", "data2")
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{{"alice", "data1", "read"}})

	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{{"alice", "data1", "read"}})
}

func (suite *AdapterTestSuite) TestLoadFilteredPolicy() {
	err := suite.enforcer.LoadFilteredPolicy(&bunadapter.Filter{
		P: []string{"", "", "read"},
	})
	suite.Require().NoError(err)
	suite.Assert().True(suite.enforcer.IsFiltered())
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"data2_admin", "data2", "read"},
	})
}

func (suite *AdapterTestSuite) TestLoadFilteredPolicyNilFilter() {
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", suite.adapter)
	suite.Require().NoError(err)

	err = e.LoadFilteredPolicy(nil)
	suite.Require().NoError(err)

	suite.Assert().False(e.IsFiltered())
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
}

func (suite *AdapterTestSuite) TestSavePolicyClearPreviousData() {
	suite.enforcer.EnableAutoSave(false)
	policies := suite.enforcer.GetPolicy()
	// clone slice to avoid shuffling elements
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := suite.enforcer.RemovePolicy(p)
		suite.Require().NoError(err)
	}
	policies = suite.enforcer.GetGroupingPolicy()
	policies = append(policies[:0:0], policies...)
	for _, p := range policies {
		_, err := suite.enforcer.RemoveGroupingPolicy(p)
		suite.Require().NoError(err)
	}
	suite.assertEnforcerPolicy([][]string{})

	err := suite.enforcer.SavePolicy()
	suite.Require().NoError(err)

	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)
	suite.assertEnforcerPolicy([][]string{})
}

func (suite *AdapterTestSuite) TestUpdatePolicy() {
	var err error
	suite.enforcer, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)

	suite.enforcer.SetAdapter(suite.adapter)

	err = suite.enforcer.SavePolicy()
	suite.Require().NoError(err)

	_, err = suite.enforcer.UpdatePolicies([][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}, [][]string{{"bob", "data1", "read"}, {"alice", "data2", "write"}})
	suite.Require().NoError(err)

	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	})
}

func (suite *AdapterTestSuite) TestUpdatePolicyWithLoadFilteredPolicy() {
	var err error
	suite.enforcer, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)

	suite.enforcer.SetAdapter(suite.adapter)

	err = suite.enforcer.SavePolicy()
	suite.Require().NoError(err)

	err = suite.enforcer.LoadFilteredPolicy(&bunadapter.Filter{P: []string{"data2_admin"}})
	suite.Require().NoError(err)

	_, err = suite.enforcer.UpdatePolicies(suite.enforcer.GetPolicy(), [][]string{{"bob", "data2", "read"}, {"alice", "data2", "write"}})
	suite.Require().NoError(err)

	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
	})
}

func (suite *AdapterTestSuite) TestUpdateFilteredPolicies() {

	var err error
	suite.enforcer, err = casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	suite.Require().NoError(err)

	suite.enforcer.SetAdapter(suite.adapter)

	err = suite.enforcer.SavePolicy()
	suite.Require().NoError(err)

	_, err = suite.adapter.UpdateFilteredPolicies("p", "p", [][]string{{"alice", "data2", "write"}}, 0, "alice", "data1", "read")
	suite.Require().NoError(err)
	_, err = suite.adapter.UpdateFilteredPolicies("p", "p", [][]string{{"bob", "data1", "read"}}, 0, "bob", "data2", "write")
	suite.Require().NoError(err)

	err = suite.enforcer.LoadPolicy()
	suite.Require().NoError(err)

	suite.assertEnforcerPolicy([][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"alice", "data2", "write"},
		{"bob", "data1", "read"},
	})
}
