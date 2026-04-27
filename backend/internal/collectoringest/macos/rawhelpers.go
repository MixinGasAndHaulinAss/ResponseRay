package macos

import (
	"fmt"
	"os"
)

// exists returns nil if path exists.
func exists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, err
	}
	return true, nil
}

// sqlValue normalizes a sqlite scan value for json marshaling. byte slices
// from BLOB columns are surfaced as hex strings so we never attempt to
// utf8-decode random key material.
func sqlValue(v interface{}) interface{} {
	switch t := v.(type) {
	case []byte:
		if len(t) > 0 {
			return fmt.Sprintf("blob:%d", len(t))
		}
		return ""
	case nil:
		return nil
	default:
		return v
	}
}

func asString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func asInt64(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int32:
		return int64(t), true
	case int:
		return int64(t), true
	case float64:
		return int64(t), true
	case uint64:
		return int64(t), true
	default:
		return 0, false
	}
}

func asInt64Default(v interface{}, def int64) int64 {
	if i, ok := asInt64(v); ok {
		return i
	}
	return def
}
