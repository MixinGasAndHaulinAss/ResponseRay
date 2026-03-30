package scanner

import (
	"compress/zlib"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// decodeB64Chunk decodes base64 content with optional zlib decompression.
func decodeB64Chunk(b64 []byte) []byte {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(decoded, b64)
	if err != nil {
		n, err = base64.RawStdEncoding.Decode(decoded, b64)
		if err != nil {
			return nil
		}
	}
	decoded = decoded[:n]

	if len(decoded) > 2 && decoded[0] == 0x78 {
		r, err := zlib.NewReader(io.NopCloser(&bytesReaderAt{data: decoded}))
		if err == nil {
			decompressed, err := io.ReadAll(r)
			r.Close()
			if err == nil {
				return decompressed
			}
		}
	}
	return decoded
}

type bytesReaderAt struct {
	data []byte
	pos  int
}

func (r *bytesReaderAt) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// writeArtifact writes decoded file content to the artifacts directory,
// preserving the Windows path structure.
func writeArtifact(artifactsDir, winPath, filename string, content []byte) string {
	dirPart := sanitizeWindowsPath(winPath, filename)
	fullDir := filepath.Join(artifactsDir, dirPart)
	if err := os.MkdirAll(fullDir, 0o755); err != nil {
		return ""
	}
	diskPath := filepath.Join(fullDir, filename)
	if err := os.WriteFile(diskPath, content, 0o644); err != nil {
		return ""
	}
	return diskPath
}

// sanitizeWindowsPath converts a Windows path to a safe local directory path.
func sanitizeWindowsPath(winPath, filename string) string {
	if winPath == "" {
		return "unknown"
	}
	p := strings.TrimPrefix(winPath, "\\\\?\\")
	p = strings.TrimPrefix(p, "\\??\\")
	p = strings.ReplaceAll(p, "\\", "/")
	if len(p) >= 2 && p[1] == ':' {
		p = string(p[0]) + p[2:]
	}
	if filename != "" && strings.HasSuffix(p, "/"+filename) {
		p = p[:len(p)-len(filename)-1]
	} else if p == filename {
		return "root"
	}
	p = filepath.Clean(p)
	if p == "." || p == "" {
		return "unknown"
	}
	return p
}
