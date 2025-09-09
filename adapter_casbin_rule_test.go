package bunadapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCasbinRule(t *testing.T) {
	cases := []struct {
		name  string
		ptype string
		rule  [6]string
	}{
		{
			name:  "basic p policy",
			ptype: "p",
			rule:  [6]string{"alice", "data1", "read", "", "", ""},
		},
		{
			name:  "grouping g policy with fewer fields",
			ptype: "g",
			rule:  [6]string{"bob", "group1", "", "", "", ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := newCasbinRule(tc.ptype, tc.rule[:]) // convert array to slice for the function
			assert.NotNil(t, got, "newCasbinRule returned nil")

			// Assert ptype directly
			assert.Equal(t, tc.ptype, got.Ptype, "ptype mismatch")

			// Assert V0..V5 individually.
			assert.Equal(t, tc.rule[0], got.V0, "V0 mismatch")
			assert.Equal(t, tc.rule[1], got.V1, "V1 mismatch")
			assert.Equal(t, tc.rule[2], got.V2, "V2 mismatch")
			assert.Equal(t, tc.rule[3], got.V3, "V3 mismatch")
			assert.Equal(t, tc.rule[4], got.V4, "V4 mismatch")
			assert.Equal(t, tc.rule[5], got.V5, "V5 mismatch")
		})
	}
}

func TestNewCasbinRuleIDsAreDifferent(t *testing.T) {
	rule1 := newCasbinRule("p", []string{"alice", "data1", "read", "", "", ""})
	rule2 := newCasbinRule("p", []string{"bob", "data2", "write", "", "", ""})

	assert.NotEqual(t, rule1.ID, rule2.ID, "IDs of consecutively created rules should be different")
}

func TestNewIdenticalCasbinRulesIDsAreDifferent(t *testing.T) {
	rule1 := newCasbinRule("p", []string{"alice", "data1", "read", "", "", ""})
	rule2 := newCasbinRule("p", []string{"alice", "data1", "read", "", "", ""})

	assert.NotEqual(t, rule1.ID, rule2.ID, "IDs of consecutively created rules should be different")
}
