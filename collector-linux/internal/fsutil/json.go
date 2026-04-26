package fsutil

import (
	"encoding/json"
	"io"
)

func newPrettyEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc
}
