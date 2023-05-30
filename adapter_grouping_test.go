package bunadapter_test

func (suite *AdapterTestSuite) TestAddExistingGroupingPolicy() {
	suite.False(suite.enforcer.AddGroupingPolicy("alice", "data2_admin"))
	suite.assertAllowed("alice", "data2", "write")
	suite.assertDisallowed("alice", "data1", "write")
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
}

func (suite *AdapterTestSuite) TestAddNotExistingGroupingPolicy() {
	suite.True(suite.enforcer.AddGroupingPolicy("alice", "data1_admin"))
	suite.True(suite.enforcer.AddPolicy("data1_admin", "data1", "read"))
	suite.True(suite.enforcer.AddPolicy("data1_admin", "data1", "write"))
	suite.assertAllowed("alice", "data2", "write")
	suite.assertAllowed("alice", "data1", "write")
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"data1_admin", "data1", "read"},
		{"data1_admin", "data1", "write"},
	})
}

func (suite *AdapterTestSuite) TestAddNewHierarchicalGroupingPolicy() {
	suite.True(suite.enforcer.AddGroupingPolicy("admin", "data1_admin"))
	suite.True(suite.enforcer.AddPolicy("data1_admin", "data1", "read"))
	suite.True(suite.enforcer.AddPolicy("data1_admin", "data1", "write"))

	suite.True(suite.enforcer.AddGroupingPolicy("admin", "data2_admin"))
	suite.True(suite.enforcer.AddGroupingPolicy("joe", "admin"))

	suite.assertAllowed("joe", "data1", "read")
	suite.assertAllowed("joe", "data1", "write")
	suite.assertAllowed("joe", "data2", "read")
	suite.assertAllowed("joe", "data2", "write")
	suite.assertDisallowed("joe", "data3", "read")
	suite.assertDisallowed("joe", "data3", "write")
	suite.assertEnforcerPolicy([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"data1_admin", "data1", "read"},
		{"data1_admin", "data1", "write"},
	})
}
