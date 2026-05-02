package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type ApplicationLogsCollector struct{}

func (c *ApplicationLogsCollector) Name() string { return "ApplicationLogs" }
func (c *ApplicationLogsCollector) Description() string {
	return "Logs and config for nginx/apache/mysql/postgres/redis/memcached/docker/k8s/various daemons"
}

func (c *ApplicationLogsCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	type entry struct {
		Label string
		Roots []string
		Exts  []string
	}

	apps := []entry{
		{"nginx", []string{"/etc/nginx", "/var/log/nginx"}, []string{".log", ".conf", ".gz"}},
		{"apache", []string{"/etc/apache2", "/etc/httpd", "/var/log/apache2", "/var/log/httpd"}, []string{".log", ".conf", ".gz"}},
		{"mysql", []string{"/etc/mysql", "/var/log/mysql"}, []string{".cnf", ".log", ".err", ".gz"}},
		{"mariadb", []string{"/etc/mariadb"}, []string{".cnf", ".conf"}},
		{"postgres", []string{"/etc/postgresql", "/var/log/postgresql"}, []string{".conf", ".log", ".gz"}},
		{"redis", []string{"/etc/redis", "/var/log/redis"}, []string{".conf", ".log"}},
		{"memcached", []string{"/etc/memcached.conf", "/var/log/memcached.log"}, []string{".conf", ".log"}},
		{"haproxy", []string{"/etc/haproxy", "/var/log/haproxy.log"}, []string{".cfg", ".log"}},
		{"varnish", []string{"/etc/varnish", "/var/log/varnish"}, []string{".vcl", ".log"}},
		{"openvpn", []string{"/etc/openvpn", "/var/log/openvpn"}, []string{".conf", ".log"}},
		{"wireguard", []string{"/etc/wireguard"}, []string{".conf"}},
		{"strongswan", []string{"/etc/strongswan", "/etc/ipsec.conf"}, []string{".conf"}},
		{"squid", []string{"/etc/squid", "/var/log/squid"}, []string{".conf", ".log"}},
		{"bind", []string{"/etc/bind", "/var/named", "/var/log/named"}, []string{".conf", ".log"}},
		{"dnsmasq", []string{"/etc/dnsmasq.conf", "/etc/dnsmasq.d"}, []string{".conf"}},
		{"dovecot", []string{"/etc/dovecot", "/var/log/dovecot"}, []string{".conf", ".log"}},
		{"postfix", []string{"/etc/postfix", "/var/log/maillog", "/var/log/mail.log"}, []string{".conf", ".cf", ".log"}},
		{"openldap", []string{"/etc/openldap", "/var/log/slapd"}, []string{".conf", ".log"}},
		{"samba", []string{"/etc/samba", "/var/log/samba"}, []string{".conf", ".log"}},
		{"docker", []string{"/etc/docker", "/var/log/docker.log", "/var/lib/docker/containers"}, []string{".json", ".log", "json.log"}},
		{"k8s_kubelet", []string{"/etc/kubernetes", "/var/log/kubernetes"}, []string{".conf", ".log", ".yaml"}},
		{"crowdstrike", []string{"/opt/CrowdStrike"}, []string{".log", ".txt"}},
		{"sentinelone", []string{"/opt/sentinelone"}, []string{".log", ".txt"}},
		{"qualys", []string{"/opt/qualys"}, []string{".log", ".txt"}},
		{"rapid7", []string{"/opt/rapid7"}, []string{".log", ".txt"}},
	}

	for _, e := range apps {
		for _, root := range e.Roots {
			info, err := stat(root)
			if err != nil {
				continue
			}
			if !info.IsDir() {
				ctx.CaptureFile(root, "artifacts/applogs/"+e.Label+"/"+filepath.Base(root), "application_logs")
				r.FilesCollected++
				continue
			}
			count := ctx.CaptureGlob(root,
				func(p string, info fs.FileInfo) bool {
					ext := strings.ToLower(filepath.Ext(p))
					if len(e.Exts) == 0 {
						return true
					}
					for _, allow := range e.Exts {
						if strings.Contains(strings.ToLower(p), allow) {
							return true
						}
					}
					_ = ext
					return false
				},
				func(p string) string {
					rel, _ := filepath.Rel(filepath.Dir(root), p)
					return filepath.Join("artifacts/applogs", e.Label, rel)
				},
				"application_logs")
			r.FilesCollected += count
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
