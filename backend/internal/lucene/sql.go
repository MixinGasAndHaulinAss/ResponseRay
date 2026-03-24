package lucene

import (
	"fmt"
	"strings"
)

var topLevelColumns = map[string]string{
	"event_type":      "event_type",
	"message":         "message",
	"host_name":       "host_name",
	"source_short":    "source_short",
	"data_type":       "data_type",
	"timestamp_desc":  "timestamp_desc",
	"ct_significance": "ct_significance",
	"finding":         "finding",
	"finding_note":    "finding_note",
	"is_suspicious":   "is_suspicious",
}

type SQLResult struct {
	Clause string
	Args   []interface{}
}

func ToSQL(node Node, startIdx int) (*SQLResult, error) {
	if node == nil {
		return &SQLResult{Clause: "TRUE"}, nil
	}
	b := &sqlBuilder{argIdx: startIdx}
	clause, err := b.build(node)
	if err != nil {
		return nil, err
	}
	return &SQLResult{Clause: clause, Args: b.args}, nil
}

type sqlBuilder struct {
	argIdx int
	args   []interface{}
}

func (b *sqlBuilder) addArg(val interface{}) string {
	placeholder := fmt.Sprintf("$%d", b.argIdx)
	b.args = append(b.args, val)
	b.argIdx++
	return placeholder
}

func (b *sqlBuilder) build(node Node) (string, error) {
	switch n := node.(type) {
	case *FieldNode:
		return b.buildField(n)
	case *NotNode:
		child, err := b.build(n.Child)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("NOT (%s)", child), nil
	case *AndNode:
		left, err := b.build(n.Left)
		if err != nil {
			return "", err
		}
		right, err := b.build(n.Right)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%s AND %s)", left, right), nil
	case *OrNode:
		left, err := b.build(n.Left)
		if err != nil {
			return "", err
		}
		right, err := b.build(n.Right)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%s OR %s)", left, right), nil
	default:
		return "", fmt.Errorf("unknown node type: %T", node)
	}
}

func (b *sqlBuilder) buildField(n *FieldNode) (string, error) {
	col, isTopLevel := topLevelColumns[n.Field]

	if n.Exists {
		if isTopLevel {
			return fmt.Sprintf("%s IS NOT NULL", col), nil
		}
		return fmt.Sprintf("data ? %s", b.addArg(n.Field)), nil
	}

	if isTopLevel {
		if n.Field == "is_suspicious" {
			val := strings.ToLower(n.Value)
			if val == "true" || val == "1" || val == "yes" {
				return "is_suspicious = TRUE", nil
			}
			return "is_suspicious = FALSE", nil
		}
		if n.Field == "message" {
			if n.Wildcard {
				return fmt.Sprintf("LOWER(%s) LIKE LOWER(%s)", col, b.addArg("%"+n.Value+"%")), nil
			}
			return fmt.Sprintf("LOWER(%s) LIKE LOWER(%s)", col, b.addArg("%"+n.Value+"%")), nil
		}
		if n.Wildcard {
			return fmt.Sprintf("%s ILIKE %s", col, b.addArg(n.Value+"%")), nil
		}
		return fmt.Sprintf("%s = %s", col, b.addArg(n.Value)), nil
	}

	// JSONB field
	jsonAccess := fmt.Sprintf("data->>'%s'", strings.ReplaceAll(n.Field, "'", "''"))
	if n.Wildcard {
		return fmt.Sprintf("%s ILIKE %s", jsonAccess, b.addArg(n.Value+"%")), nil
	}
	return fmt.Sprintf("%s = %s", jsonAccess, b.addArg(n.Value)), nil
}

// ArgCount returns the number of arguments added during SQL generation.
func (r *SQLResult) ArgCount() int {
	return len(r.Args)
}

// NextArgIdx returns the next available parameter index after this result.
func (r *SQLResult) NextArgIdx(startIdx int) int {
	return startIdx + len(r.Args)
}
