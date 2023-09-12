package bunadapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/mmcloughlin/meow"
	"github.com/uptrace/bun"
)

// Filter represents adapter filter.
type Filter struct {
	P []string
	G []string
}

// Adapter represents the github.com/uptrace/bun adapter for policy storage.
type Adapter struct {
	db       *bun.DB
	filtered bool
}

// NewAdapter creates new Adapter by using bun's database connection.
// Expects DB table to be created in database.
func NewAdapter(db *bun.DB) (*Adapter, error) {
	return &Adapter{db: db}, nil
}

// LoadPolicy loads policy from the database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var rules []*CasbinRule

	if err := a.db.NewSelect().Model(&rules).Scan(context.Background()); err != nil {
		return fmt.Errorf("failed to load policy from adapter db: %w", err)
	}

	for _, r := range rules {
		persist.LoadPolicyLine(r.String(), model)
	}

	a.filtered = false

	return nil
}

// SavePolicy saves policy to the database removing any policies already present.
func (a *Adapter) SavePolicy(model model.Model) error {
	rules := a.extractRules(model)

	if err := a.save(true, rules...); err != nil {
		return fmt.Errorf("failed to save policy to adapter db: %w", err)
	}

	return nil
}

// AddPolicy adds adapter policy rule to the database.
func (a *Adapter) AddPolicy(_ string, ptype string, rule []string) error {
	r := newCasbinRule(ptype, rule)

	if err := a.save(false, r); err != nil {
		return fmt.Errorf("failed to add adapter policy rule: %w", err)
	}

	return nil
}

// AddPolicies adds policy rules to the database.
func (a *Adapter) AddPolicies(_ string, ptype string, rules [][]string) error {
	casbinRules := make([]*CasbinRule, 0, len(rules))
	for _, rule := range rules {
		casbinRules = append(casbinRules, newCasbinRule(ptype, rule))
	}

	if err := a.save(false, casbinRules...); err != nil {
		return fmt.Errorf("failed to add policy rules: %w", err)
	}

	return nil
}

// RemovePolicy removes adapter policy rule from the database.
func (a *Adapter) RemovePolicy(_ string, ptype string, rule []string) error {
	r := newCasbinRule(ptype, rule)

	if err := a.delete(r); err != nil {
		return fmt.Errorf("failed to remove adapter policy rule: %w", err)
	}

	return nil
}

// RemovePolicies removes policy rules from the database.
func (a *Adapter) RemovePolicies(_ string, ptype string, rules [][]string) error {
	var casbinRules []*CasbinRule
	for _, rule := range rules {
		casbinRules = append(casbinRules, newCasbinRule(ptype, rule))
	}

	if err := a.delete(casbinRules...); err != nil {
		return fmt.Errorf("failed to remove policy rules: %w", err)
	}

	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the database.
func (a *Adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := a.db.NewDelete().Model((*CasbinRule)(nil)).Where("ptype = ?", ptype)

	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 && fieldValues[0-fieldIndex] != "" {
		query = query.Where("v0 = ?", fieldValues[0-fieldIndex])
	}
	if fieldIndex <= 1 && idx > 1 && fieldValues[1-fieldIndex] != "" {
		query = query.Where("v1 = ?", fieldValues[1-fieldIndex])
	}
	if fieldIndex <= 2 && idx > 2 && fieldValues[2-fieldIndex] != "" {
		query = query.Where("v2 = ?", fieldValues[2-fieldIndex])
	}
	if fieldIndex <= 3 && idx > 3 && fieldValues[3-fieldIndex] != "" {
		query = query.Where("v3 = ?", fieldValues[3-fieldIndex])
	}
	if fieldIndex <= 4 && idx > 4 && fieldValues[4-fieldIndex] != "" {
		query = query.Where("v4 = ?", fieldValues[4-fieldIndex])
	}
	if fieldIndex <= 5 && idx > 5 && fieldValues[5-fieldIndex] != "" {
		query = query.Where("v5 = ?", fieldValues[5-fieldIndex])
	}

	_, err := query.Exec(context.Background())
	if err != nil {
		return fmt.Errorf("failed to remove filtered policy: %w", err)
	}

	return nil
}

// LoadFilteredPolicy loads adapter policy from the database that matches the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}

	filterValue, ok := filter.(*Filter)
	if !ok {
		return fmt.Errorf("invalid filter type")
	}

	err := a.loadFilteredPolicy(model, filterValue)
	if err != nil {
		return err
	}
	a.filtered = true
	return nil
}

func (a *Adapter) loadFilteredPolicy(model model.Model, filter *Filter) error {
	if filter.P != nil {
		var lines []*CasbinRule

		query := a.db.NewSelect().Model(&lines).Where("ptype = 'p'")
		query, err := a.buildQuery(query, filter.P)
		if err != nil {
			return err
		}
		err = query.Scan(context.Background())
		if err != nil {
			return err
		}

		for _, line := range lines {
			persist.LoadPolicyLine(line.String(), model)
		}
	}
	if filter.G != nil {
		var lines []*CasbinRule

		query := a.db.NewSelect().Model(&lines).Where("ptype = 'g'")
		query, err := a.buildQuery(query, filter.G)
		if err != nil {
			return err
		}
		err = query.Scan(context.Background())
		if err != nil {
			return err
		}

		for _, line := range lines {
			persist.LoadPolicyLine(line.String(), model)
		}
	}
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

// UpdatePolicy updates adapter policy rule from the database.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePolicies(sec, ptype, [][]string{oldRule}, [][]string{newPolicy})
}

// UpdatePolicies updates some policy rules to the database.
func (a *Adapter) UpdatePolicies(_ string, ptype string, oldRules, newRules [][]string) error {
	oldLines := make([]*CasbinRule, 0, len(oldRules))
	newLines := make([]*CasbinRule, 0, len(newRules))

	for _, rule := range oldRules {
		oldLines = append(oldLines, newCasbinRule(ptype, rule))
	}

	for _, rule := range newRules {
		newLines = append(newLines, newCasbinRule(ptype, rule))
	}

	tx, err := a.db.Begin()
	if err != nil {
		return err
	}

	for i, line := range oldLines {
		str, args := line.queryString()
		_, err = tx.NewUpdate().Model(newLines[i]).Where(str, args...).Exec(context.Background())
		if err != nil {
			tx.Rollback()

			return err
		}
	}

	return tx.Commit()
}

// UpdateFilteredPolicies updates some policy rules in the database.
func (a *Adapter) UpdateFilteredPolicies(_ string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	line := &CasbinRule{}

	line.Ptype = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newP := make([]CasbinRule, 0, len(newRules))
	for _, nr := range newRules {
		newP = append(newP, *(newCasbinRule(ptype, nr)))
	}

	oldP := make([]CasbinRule, 0)
	oldP = append(oldP, *line)

	err := a.db.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
		for i := range newP {
			str, args := line.queryString()
			result, err := tx.NewDelete().Model(&oldP).Where(str, args...).Returning("*").Exec(ctx)
			fmt.Println(result)
			if err != nil {
				return err
			}

			_, err = tx.NewInsert().Model(&newP[i]).On("CONFLICT DO NOTHING").Exec(ctx)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// return deleted rules
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, nil
}

// Close closes adapter database connection.
func (a *Adapter) Close() error {
	return a.db.Close()
}

func (a *Adapter) extractRules(model model.Model) []*CasbinRule {
	var casbinRules []*CasbinRule

	for ptype, assertion := range model["p"] {
		for _, rule := range assertion.Policy {
			casbinRules = append(casbinRules, newCasbinRule(ptype, rule))
		}
	}

	for ptype, assertion := range model["g"] {
		for _, rule := range assertion.Policy {
			casbinRules = append(casbinRules, newCasbinRule(ptype, rule))
		}
	}

	return casbinRules
}

func (a *Adapter) save(truncate bool, lines ...*CasbinRule) error {
	return a.db.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
		if truncate {
			_, err := tx.NewTruncateTable().Model((*CasbinRule)(nil)).Exec(context.Background())
			if err != nil {
				return err
			}
		}

		for _, line := range lines {
			_, err := tx.NewInsert().Model(line).On("CONFLICT DO NOTHING").Exec(context.Background())
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (a *Adapter) delete(lines ...*CasbinRule) error {
	_, err := a.db.NewDelete().Model(&lines).WherePK().Exec(context.Background())

	return err
}

func (a *Adapter) buildQuery(query *bun.SelectQuery, values []string) (*bun.SelectQuery, error) {
	for ind, v := range values {
		if v == "" {
			continue
		}
		switch ind {
		case 0:
			query = query.Where("v0 = ?", v)
		case 1:
			query = query.Where("v1 = ?", v)
		case 2:
			query = query.Where("v2 = ?", v)
		case 3:
			query = query.Where("v3 = ?", v)
		case 4:
			query = query.Where("v4 = ?", v)
		case 5:
			query = query.Where("v5 = ?", v)
		default:
			return nil, fmt.Errorf("filter has more values than expected, should not exceed 6 values")
		}
	}
	return query, nil
}

// CasbinRule represents adapter rule in Casbin.
type CasbinRule struct {
	bun.BaseModel `bun:"table:casbin.casbin_rules,alias:cr"`

	ID    string `bun:",pk"`
	Ptype string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

func newCasbinRule(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{Ptype: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	line.ID = line.policyID(ptype, rule)

	return line
}

func (r *CasbinRule) String() string {
	const prefixLine = ", "
	var sb strings.Builder

	sb.Grow(
		len(r.Ptype) +
			len(r.V0) + len(r.V1) + len(r.V2) +
			len(r.V3) + len(r.V4) + len(r.V5),
	)

	sb.WriteString(r.Ptype)
	if len(r.V0) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V0)
	}
	if len(r.V1) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V1)
	}
	if len(r.V2) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V2)
	}
	if len(r.V3) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V3)
	}
	if len(r.V4) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V4)
	}
	if len(r.V5) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V5)
	}

	return sb.String()
}

func (r *CasbinRule) policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))

	return fmt.Sprintf("%x", sum)
}

func (r *CasbinRule) queryString() (string, []interface{}) {
	queryArgs := []interface{}{r.Ptype}

	queryStr := "ptype = ?"
	if r.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, r.V0)
	}
	if r.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, r.V1)
	}
	if r.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, r.V2)
	}
	if r.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, r.V3)
	}
	if r.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, r.V4)
	}
	if r.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, r.V5)
	}

	return queryStr, queryArgs
}

func (r *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0, 7)

	if r.Ptype != "" {
		policy = append(policy, r.Ptype)
	}
	if r.V0 != "" {
		policy = append(policy, r.V0)
	}
	if r.V1 != "" {
		policy = append(policy, r.V1)
	}
	if r.V2 != "" {
		policy = append(policy, r.V2)
	}
	if r.V3 != "" {
		policy = append(policy, r.V3)
	}
	if r.V4 != "" {
		policy = append(policy, r.V4)
	}
	if r.V5 != "" {
		policy = append(policy, r.V5)
	}

	return policy
}
