# ResponseRay ESXi Collector

A POSIX shell script that captures forensic artifacts from a running VMware ESXi host. Produces a `tar.gz` archive with the same `manifest.json` schema as the Windows, Linux, and macOS collectors, ready for upload to the [ResponseRay](https://github.com/NCLGISA/ResponseRay) platform.

**Current version:** `2026.4.29.1`

## Key Design Principles

- **Native shell only** — `/bin/sh` (BusyBox `ash`), no bash, no Python, no Go runtime needed. Drop the script on the host and run.
- **In-OS capture** — uses `esxcli`, `vim-cmd`, `vmkfstools`, `vsish`, `esxtop`, and direct file copies. No raw disk imaging.
- **VM metadata only** — captures `.vmx`, `.vmsd`, `.nvram`, `vmware*.log` (small descriptors and logs), but does NOT copy `.vmdk` payloads. To preserve VM disks, use vSphere snapshot or storage-level imaging separately.
- **Comprehensive ESXi coverage** — 35+ evidence types across host config, hostd/vpxa logs, syslog, firewall, AD/SSO, vSAN, NSX/dvSwitch, secure-boot/TPM/keystore, VIB signatures, plus per-VM snapshot trees and vmkfstools per-volume stats.
- **Optional memory** — `--include-memory` captures `/var/core/*` and `/vmkernel-zdump*` (off by default; large)

## Requirements

- **root** — required to read host config, hostd/vpxa logs, and per-VM `.vmx` files
- **VMware ESXi 7.0 or later** — older versions may lack some `esxcli` namespaces; the collector logs and continues on missing commands
- **A writable destination** — `/var/tmp` by default; for hosts with limited bootbank space, point `--output` at a VMFS datastore (e.g., `/vmfs/volumes/datastore1`)

## Quick Start

Copy the script to the host (via SCP after enabling SSH on the host):

```bash
scp collector-esxi/responseray-collector-esxi.sh root@esxi-host:/tmp/
ssh root@esxi-host
chmod +x /tmp/responseray-collector-esxi.sh
/tmp/responseray-collector-esxi.sh --output /vmfs/volumes/datastore1
```

The collector will produce `ResponseRay_<host>_<ts>.tar.gz` next to the output directory. Move it off the host:

```bash
scp root@esxi-host:/vmfs/volumes/datastore1/ResponseRay_*.tar.gz .
```

Upload the `.tar.gz` through the ResponseRay web UI.

## Command Line Options

```
responseray-collector-esxi.sh [--output DIR] [--include-memory] [--skip name1,name2]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--output <dir>` | Base directory for collection + archive | `/var/tmp` |
| `--include-memory` | Capture `/vmkernel-zdump*` and process core dumps | Disabled |
| `--skip <list>` | Comma-separated collector module names to skip | None |

### Examples

```bash
/tmp/responseray-collector-esxi.sh --output /vmfs/volumes/datastore1

/tmp/responseray-collector-esxi.sh --skip VMs,Storage --output /vmfs/volumes/datastore1

/tmp/responseray-collector-esxi.sh --include-memory --output /vmfs/volumes/datastore1
```

## Collectors

| Collector | Description |
|-----------|-------------|
| `SystemInfo` | `vmware -lv`, `esxcli system version/hostname/uuid/welcomemsg/settings advanced/settings kernel/module list/boot device/maintenanceMode`, `uname -a`, `uptime`, `date -u`, `esxcli system time get` |
| `UsersAuth` | `/etc/{passwd,shadow,group,sudoers}`, `/etc/sudoers.d/*`, `/etc/pam.d/*`, `/etc/security/*`, `/etc/sssd/sssd.conf`, `esxcli system account list`, `esxcli system permission list`, `vim-cmd hostsvc/lockdown_is_enabled`, `who`, `last` |
| `SystemLogs` | `/var/log/*.log*`, `/var/run/log/{auth,hostd,vpxa,vmkernel,vmkwarning,shell,syslog,usb,storagerm}.log`, `esxcli system syslog config/logger`, `esxcli system coredump partition/file list` |
| `ShellHistory` | `.ash_history`, `.bash_history`, `.sh_history`, `.history`, `.lesshst`, `.viminfo` per user (`/root` and `/home/*`) |
| `SSH` | `/etc/ssh/{sshd_config,ssh_config,*}`, per-user `~/.ssh/*`, `esxcli system ssh server config list`, `esxcli network firewall ruleset list` |
| `Network` | `/etc/{hosts,resolv.conf,services}`, `esxcli network ip interface/ip route ipv4/ip route ipv6/ip dns server/ip dns search/vswitch standard/vswitch dvs vmware/portgroup/nic/nic stats/ip neighbor/ip connection`, `esxcfg-route -l` |
| `Firewall` | `esxcli network firewall get/ruleset list/ruleset rule list/ruleset allowedip list`, `/etc/vmware/firewall/*.xml`, `/etc/vmware/service.xml` |
| `Storage` | `esxcli storage filesystem/vmfs extent/core device/core path/core adapter/iscsi adapter/nfs/nfs41/vsan cluster/vvol storagecontainer`, `df -h`, `mount` |
| `VMs` | `vim-cmd vmsvc/getallvms`, per VM: `power.getstate`, `get.summary`, `get.config`, `get.guest`, `get.runtime`, `get.snapshotinfo`, `device.getdevices`. Also captures every registered VM's `.vmx`, `.vmsd`, `.nvram`, and `vmware*.log`. `vmkfstools -P /vmfs/volumes` |
| `Processes` | `esxcli system process list`, `ps -Pwwc`, `esxtop -b -n 1`, `lsof`, `vsish -e get /memory/comprehensive` |
| `KernelModules` | `esxcli system module list`, `esxcli software vib list`, `esxcli software acceptance get`, `esxcli software vib signature verify`, `esxcli software profile get` |
| `Security` | Encryption / TPM / Keystore status (`esxcli system settings encryption get`, `esxcli hardware trustedboot get`, `esxcli system security keypersistence get`), machine certificate dump, `/etc/vmware/ssl/*`, vCenter cert chain |
| `Config` | `/etc/vmware/esx.conf`, `hostd/config.xml`, `vpxa/vpxa.cfg`, `snmp.xml`, `inetd.conf`, `/etc/profile`, `/etc/rc.local.d/*`, `/bootbank/boot.cfg` |
| `Persistence` | `/etc/init.d/*`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`, `/etc/crontab`, `rc.local`, `local.sh`, `/etc/profile`, root shell init files |
| `Hardware` | `esxcli hardware cpu/memory/pci/clock/platform`, `smbiosDump`, `lspci -p`, `esxcli hardware usb passthrough device list` |
| `Software` | `esxcli software vib list`, `esxcli software vib get` (all), `esxcli software profile get`, `esxcli software baseimage get/component list` |
| `MemoryArtifacts` | `/var/core/*`, `/vmkernel-zdump*` (only with `--include-memory`); `esxcli system coredump partition/file get` |

## Output Format

The collector produces `ResponseRay_<host>_<ts>.tar.gz` containing:

```
manifest.json              # platform = "esxi"
artifacts/
  auth/                    # passwd, shadow, group, sudoers, pam.d, security
  config/                  # esx.conf, hostd config, vpxa config, snmp.xml
  firewall/                # firewall ruleset XML
  network/                 # hosts, resolv.conf, services
  persistence/             # init.d, cron.d, rc.local
  security/                # certs, ssl
  shell_history/<user>/    # ash/bash/sh histories
  ssh/{system,users/<user>}/ # sshd_config, authorized_keys, etc.
  var_log/                 # All ESXi logs
  vms/                     # Per-VM .vmx, .vmsd, .nvram, vmware*.log
live/
  system_info, users, account_list, permission_list, lockdown
  esxcli_*.txt             # ~80 esxcli outputs
  vms/<id>/{power,summary,config,guest,runtime,snapshot,devices}.txt
  vmkfstools_extent.txt
  process_list, ps_world, esxtop_b, lsof, vsi_meminfo
  software_*.txt
  hardware_*.txt
collector.log              # Live collector log
```

## How It Works

The script uses only POSIX `sh` constructs: no bashisms, arrays, or process substitution. It walks a deterministic list of file/command targets, capturing each into the output tree, computing total size in bytes, and emitting a manifest.json that matches the cross-platform schema (`platform: "esxi"`, `vss_used: false`).

For VMs, the collector iterates `vim-cmd vmsvc/getallvms` and grabs metadata for each. It deliberately does **not** copy `.vmdk` files — to preserve VM disks for later analysis, take a vSphere snapshot or use storage-level imaging on the underlying datastore.

## Compatibility

| ESXi | Status |
|------|--------|
| 8.0 U2 | Tested |
| 8.0 | Tested |
| 7.0 U3 | Tested |
| 7.0 | Tested |
| 6.7 | Expected to work (some esxcli namespaces missing; logged + continued) |

## Limitations

- ESXi's BusyBox lacks GNU `find -printf` and other niceties, so the collector relies on `wc -c` and `cp` for sizing/copying.
- The shell script does not capture full VMDK contents. For full VM imaging, snapshot at the storage layer.
- `--include-memory` artifacts can be very large (multi-GB) — point `--output` at a VMFS datastore with sufficient free space.

## License

Internal use — Currituck County, NC.
