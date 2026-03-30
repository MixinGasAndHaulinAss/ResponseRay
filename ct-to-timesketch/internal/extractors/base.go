package extractors

import (
	"compress/zlib"
	"encoding/base64"
	"io"
	"os"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
)

// GetFileContent returns the decoded binary content of a collected file.
// Prefers DiskPath (native file on disk), then pre-decoded Content, then base64.
func GetFileContent(cf cache.CollectedFile) ([]byte, error) {
	if cf.DiskPath != "" {
		return os.ReadFile(cf.DiskPath)
	}
	if cf.Content != nil {
		return cf.Content, nil
	}
	return DecodeFileContent(cf.ContentB64)
}

// Extractor is the interface all artifact extractors implement.
type Extractor interface {
	Name() string
	Description() string
	Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error)
}

// Registry holds all registered extractors.
var Registry = map[string]Extractor{}

// Register adds an extractor to the global registry.
func Register(e Extractor) {
	Registry[e.Name()] = e
}

// Get returns a registered extractor by name, or nil.
func Get(name string) Extractor {
	return Registry[name]
}

// ListNames returns all registered extractor names.
func ListNames() []string {
	names := make([]string, 0, len(Registry))
	for n := range Registry {
		names = append(names, n)
	}
	return names
}

// DecodeFileContent decodes base64 content, decompressing zlib if needed.
func DecodeFileContent(b64 []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(decoded, b64)
	if err != nil {
		// Try RawStdEncoding (no padding)
		n, err = base64.RawStdEncoding.Decode(decoded, b64)
		if err != nil {
			return nil, err
		}
	}
	decoded = decoded[:n]

	// Check for zlib compression (0x78 header)
	if len(decoded) > 2 && decoded[0] == 0x78 {
		r, err := zlib.NewReader(io.NopCloser(
			&byteReader{data: decoded},
		))
		if err == nil {
			decompressed, err := io.ReadAll(r)
			r.Close()
			if err == nil {
				return decompressed, nil
			}
		}
		// Not actually zlib, return raw
	}
	return decoded, nil
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
