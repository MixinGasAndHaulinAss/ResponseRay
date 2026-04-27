// Package core - plist read helpers used by macOS LaunchDaemons /
// LaunchAgents / LoginItems / sfltool parsers.
package core

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"howett.net/plist"
)

// ReadPlist decodes any of binary, XML, or OpenStep plist files into a
// generic map. Returns nil + nil if the file is empty/unreadable so callers
// can fall through to a stub event.
func ReadPlist(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty plist")
	}
	dec := plist.NewDecoder(bytes.NewReader(data))
	var raw interface{}
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("plist decode: %w", err)
	}
	out, ok := raw.(map[string]interface{})
	if !ok {
		// Some plists are arrays at the root - wrap them.
		return map[string]interface{}{"_root": raw}, nil
	}
	// Recursively normalize: convert []byte to string when it looks like UTF-8,
	// and recurse into nested maps/slices so JSON marshaling is clean later.
	return normalizePlistMap(out), nil
}

func normalizePlistMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = normalizePlistValue(v)
	}
	return out
}

func normalizePlistValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		return normalizePlistMap(t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, item := range t {
			out[i] = normalizePlistValue(item)
		}
		return out
	case []byte:
		// If valid UTF-8 string and not too long, surface as string.
		if len(t) <= 64*1024 && isPrintableUTF8(t) {
			return string(t)
		}
		return fmt.Sprintf("<bytes:%d>", len(t))
	case uint64:
		return int64(t)
	default:
		return v
	}
}

func isPrintableUTF8(b []byte) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
		if c == 0x7f {
			return false
		}
	}
	return true
}

// PlistString returns the string value at the given key, "" if missing or
// not a string.
func PlistString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// PlistBool returns the bool value at the given key, false if missing.
func PlistBool(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// PlistStringArray returns the []string value at the given key, nil if not.
func PlistStringArray(m map[string]interface{}, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
