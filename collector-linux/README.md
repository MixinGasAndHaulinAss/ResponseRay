# ResponseRay Linux Collector

A standalone Linux forensic artifact collector. Produces a `tar.gz` archive with the same `manifest.json` schema as the Windows collector, ready for upload to the [ResponseRay](https://github.com/NCLGISA/ResponseRay) platform.

**Current version:** `2026.4.30.2`

## Key Design Principles

- **Single static binary** — Go 1.22 produces one self-contained executable; no runtime, no dependencies, runs from USB or `scp` drop
- **In-OS capture (no raw imaging)** — uses `/proc`, `/sys`, `journalctl`, `systemctl`, package managers, and direct file copies. Never reads raw disks. This works on running production systems where direct disk access is unavailable.
- **Comprehensive Linux coverage** — 165+ evidence types including auth/syslog, journald, bash/zsh history, SSH config, cron, systemd, network, firewall (iptables/nftables/ufw/firewalld), Docker, Podman, audit, MAC (SELinux/AppArmor), persistence, browsers, and more
- **Optional memory** — `--include-memory` captures `/proc/kcore`, swap files (off by default; large)
- **Minimal footprint** — collects to `/tmp`, compresses to a single `tar.gz`, cleans up after itself

## Requirements

- **root** — most paths require it (`/var/log/auth.log`, `/etc/shadow`, `journalctl --system`, etc.)
- **Linux kernel 3.10+** (RHEL 7 era and newer)
- **Go 1.22+** for building (the resulting binary is fully static)

## Quick Start

```bash
sudo ./responseray-collector-linux
```

The collector will:

1. Verify it is running as root
2. Run all 27 collectors in sequence
3. Package everything into `<host>_<timestamp>.tar.gz` in the current directory
4. Clean up its temp directory

Upload the `.tar.gz` through the ResponseRay web UI.

## Command Line Options

```
responseray-collector-linux [--output <dir>] [--skip <list>] [--include-memory]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--output <dir>` | Directory to write the output archive | Current directory |
| `--skip <list>` | Comma-separated collector names to skip (case-insensitive) | None |
| `--include-memory` | Capture `/proc/kcore`, swap, hibernation files (large) | Disabled |

### Examples

```bash
sudo ./responseray-collector-linux

sudo ./responseray-collector-linux --output /mnt/usb

sudo ./responseray-collector-linux --skip filesystem,docker

sudo ./responseray-collector-linux --include-memory --output /mnt/usb
```

## Collectors

| Collector | Description |
|-----------|-------------|
| `SystemInfo` | `/etc/os-release`, kernel version, uptime, timezone, machine-id, `uname -a`, `timedatectl`, `locale` |
| `Packages` | `dpkg -l`, `rpm -qa`, `apk info -v`, `pacman -Q`, `flatpak list`, `snap list` |
| `AuthLogs` | `/var/log/auth.log*`, `/var/log/secure*`, `last`, `lastb`, `lastlog`, faillog |
| `SystemLogs` | `/var/log/syslog*`, `/var/log/messages*`, `journalctl --system --no-pager` (last 7 days), persistent journal copy |
| `ShellHistory` | `.bash_history`, `.zsh_history`, `.sh_history`, `.lesshst`, `.viminfo`, `.python_history` per user |
| `SSH` | `/etc/ssh/sshd_config`, `ssh_config`, `sshd_config.d/`, per-user `~/.ssh/{authorized_keys,known_hosts,config,*.pub}` |
| `Cron` | `/etc/crontab`, `/etc/cron.{d,daily,hourly,weekly,monthly}`, `/var/spool/cron/crontabs/*`, `at` jobs |
| `Systemd` | All `.service`, `.timer`, `.socket` units (system + user); `systemctl list-unit-files`, `list-units`, `list-timers`, `list-jobs` |
| `Network` | `ip addr`, `ip route`, `ip neighbor`, `ss -tunap`, `arp`, `/etc/hosts`, `/etc/resolv.conf`, NetworkManager profiles |
| `Firewall` | `iptables-save`, `ip6tables-save`, `nft list ruleset`, `ufw status verbose`, `firewall-cmd --list-all` |
| `Processes` | `ps aux`, `/proc/<pid>/{cmdline,exe,cwd,environ,status,maps,fd}`, `lsof`, `ss -p` |
| `Kernel` | `lsmod`, `/proc/modules`, `/proc/version`, `/proc/cmdline`, `dmesg`, `sysctl -a` |
| `Users` | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/`, `getent` snapshots |
| `Logon` | `wtmp`, `btmp`, `utmp`, lastlog, login defs |
| `Disk` | `lsblk -O`, `blkid`, `fdisk -l`, `parted -l`, `lvs`, `vgs`, `pvs` |
| `Mount` | `mount`, `findmnt`, `df -hT`, `/etc/fstab`, `/etc/mtab`, `/proc/mounts` |
| `MAC` | SELinux: `/etc/selinux/`, `getenforce`, `sestatus`, `semodule -l`, custom policies. AppArmor: `/etc/apparmor.d/`, `aa-status` |
| `Persistence` | rc.local, profile.d, init.d, xinetd, ld.so.preload, ld.so.conf*, /etc/profile, .bash_profile, .bashrc, .zshrc per user |
| `Browser` | Firefox places.sqlite/cookies/logins, Chrome/Chromium/Brave/Opera/Vivaldi History/Cookies/Login Data/Bookmarks/Preferences per profile |
| `ApplicationLogs` | Apache `access.log`/`error.log`, Nginx, MySQL/MariaDB, PostgreSQL, Squid, Postfix, etc. |
| `Docker` | `docker info`, `docker ps -a`, `docker images`, `docker network ls`, `docker volume ls`, `docker version` |
| `Auditd` | `/etc/audit/audit.rules`, `/etc/audit/rules.d/*`, `auditctl -s`, `/var/log/audit/audit.log*`, `ausearch` summaries |
| `FileSystem` | NDJSON timeline of high-value directories (etc, bin, sbin, var/log, home, root, tmp, opt, usr/local/bin, usr/local/sbin) with full MACB |
| `MemoryArtifacts` | `/proc/kcore`, `swap` files, hibernation files (only with `--include-memory`) |
| `PkgHistory` | APT sources.list, sources.list.d, APT history logs, YUM repos, DNF config, package manager history |
| `Security` | SUID/SGID binaries, world-writable files, shared memory (ipcs), ulimit, lock files, mail spool, Sysmon for Linux |
| `MailLogs` | Mail server logs (postfix, sendmail, exim), `/var/log/mail*`, `/etc/postfix/` |
| `DHCP` | DHCP server logs and configuration, dnsmasq config |

## Output Format

```
manifest.json              # Collection metadata, file inventory, collector results
artifacts/
  system/                  # /etc/os-release, /proc/version, etc.
  packages/                # Package manager outputs
  authlogs/                # auth.log, secure, lastlog
  systemlogs/              # syslog, messages, journalctl exports
  shell_history/<user>/    # bash/zsh/sh histories
  ssh/{system,users/<user>}/  # sshd_config, known_hosts, authorized_keys
  cron/                    # crontabs, cron.d, at jobs
  systemd/                 # Unit files
  network/                 # /etc/hosts, /etc/resolv.conf, NetworkManager
  firewall/                # iptables-save output, nftables ruleset
  kernel/                  # lsmod, /proc/modules, dmesg
  users/                   # /etc/passwd, shadow, group
  logon/                   # wtmp, btmp, utmp
  disk/                    # lsblk, blkid output
  mount/                   # /etc/fstab, /etc/mtab
  mac/                     # SELinux/AppArmor configs
  persistence/             # rc.local, init.d, profile.d
  browsers/<browser>/<user>/  # Browser data
  app_logs/                # Apache, Nginx, MySQL, etc.
  docker/                  # Docker info dumps
  auditd/                  # audit.rules, audit.log
  memory/                  # (optional) kcore, swap
live/
  system_info.json
  network.json
  processes.json
  firewall.json
  ...
filesystem_timeline.ndjson # Full MACB enumeration
```

## Building

```bash
cd collector-linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '-s -w' \
  -o responseray-collector-linux ./cmd/responseray-collector-linux
```

For other architectures (e.g., ARM64 RHEL hosts):

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '-s -w' \
  -o responseray-collector-linux-arm64 ./cmd/responseray-collector-linux
```

The output is a fully static binary (~7 MB) with no glibc dependency, so it runs on any Linux kernel 3.10+ regardless of distro.

## Compatibility

| Distro | Status |
|--------|--------|
| Ubuntu 20.04 / 22.04 / 24.04 | Tested |
| Debian 11 / 12 | Tested |
| RHEL / Rocky / Alma 8 / 9 | Tested |
| Amazon Linux 2 / 2023 | Tested |
| SUSE 15 | Expected to work |
| Alpine | Works (uses `apk`) |
| Arch | Works (uses `pacman`) |

## License

Internal use — Currituck County, NC.
