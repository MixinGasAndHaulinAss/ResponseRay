package collectors

import (
	"io/fs"
	"os"
)

var statFn = func(p string) (fs.FileInfo, error) { return os.Stat(p) }

// stat is a shim used by Linux collectors so we can swap it out in tests.
func stat(p string) (fs.FileInfo, error) { return statFn(p) }
