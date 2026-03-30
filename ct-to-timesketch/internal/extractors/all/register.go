// Package all imports all extractor packages to trigger their init() registration.
package all

import (
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/browser"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/dhcp"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/entra"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/evtx"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/lnk"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/mdo"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/mft"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/powershell"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/prefetch"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/recyclebin"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/registry"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/scheduled_tasks"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/srum"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/timeline"
	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/wmi"
)
