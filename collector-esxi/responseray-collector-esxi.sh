#!/bin/sh
# ResponseRay ESXi artifact collector.
#
# Designed for VMware ESXi (/bin/sh is BusyBox ash, not bash). Uses only POSIX
# constructs and ESXi-native binaries (esxcli, vim-cmd, vmkfstools, vsish,
# nsxcli where applicable). Produces a tar.gz archive with the same manifest
# layout as the Windows / Linux / macOS collectors so the ResponseRay backend
# ingests them identically.
#
# Usage:
#   /tmp/responseray-collector-esxi.sh [--output /vmfs/volumes/<ds>] [--include-memory] [--skip name1,name2]

set -u

VERSION="2026.4.29.1"
HOSTNAME="$(hostname 2>/dev/null || echo esxi-host)"
TS_UTC="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || date -u +%Y%m%d_%H%M%S)"
TS_RFC="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u)"

OUTPUT_BASE="/var/tmp"
INCLUDE_MEMORY=0
SKIP_LIST=""

while [ $# -gt 0 ]; do
  case "$1" in
    --output)         OUTPUT_BASE="$2"; shift 2 ;;
    --include-memory) INCLUDE_MEMORY=1; shift ;;
    --skip)           SKIP_LIST="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
ResponseRay ESXi Collector $VERSION
Options:
  --output DIR       Base directory for collection (default /var/tmp)
  --include-memory   Include /vmkernel-zdump and process core dumps (large)
  --skip name1,name2 Comma list of collector module names to skip
EOF
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [ "$(id -u 2>/dev/null || echo 0)" != "0" ]; then
  echo "[!] Must be run as root for full coverage" >&2
fi

COLLECTION_NAME="ResponseRay_${HOSTNAME}_${TS_UTC}"
OUT_DIR="${OUTPUT_BASE}/${COLLECTION_NAME}"
ARTIFACTS="${OUT_DIR}/artifacts"
LIVE="${OUT_DIR}/live"
LOG="${OUT_DIR}/collector.log"

mkdir -p "$ARTIFACTS" "$LIVE" || { echo "[-] Cannot create $OUT_DIR" >&2; exit 1; }

# ---- helpers ---------------------------------------------------------------

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

skipped() {
  case ",$SKIP_LIST," in
    *",$1,"*) return 0 ;;
  esac
  return 1
}

# Manifest tracking. We store one line per file as: size|category|original|relative
MANIFEST_FILES="${OUT_DIR}/.files.tsv"
: > "$MANIFEST_FILES"

# Per-collector summaries: name|files|bytes|elapsed_ms|error
RESULTS="${OUT_DIR}/.results.tsv"
: > "$RESULTS"

CUR_FILES=0
CUR_BYTES=0

start_collector() {
  CC_NAME="$1"
  CC_START="$(date +%s 2>/dev/null || echo 0)"
  CC_FILES_BEFORE=$CUR_FILES
  CC_BYTES_BEFORE=$CUR_BYTES
  log "[ok ] starting $CC_NAME"
}

end_collector() {
  CC_END="$(date +%s 2>/dev/null || echo 0)"
  CC_ELAPSED_MS=$(( (CC_END - CC_START) * 1000 ))
  CC_FILES=$(( CUR_FILES - CC_FILES_BEFORE ))
  CC_BYTES=$(( CUR_BYTES - CC_BYTES_BEFORE ))
  printf '%s|%d|%d|%d|%s\n' "$CC_NAME" "$CC_FILES" "$CC_BYTES" "$CC_ELAPSED_MS" "${1-}" >> "$RESULTS"
  log "[done] $CC_NAME files=$CC_FILES bytes=$CC_BYTES elapsed_ms=$CC_ELAPSED_MS"
}

# capture_file SRC RELATIVE CATEGORY
capture_file() {
  src="$1"; rel="$2"; cat="$3"
  [ -f "$src" ] || return 1
  size=$(wc -c < "$src" 2>/dev/null | tr -d ' ' || echo 0)
  [ -z "$size" ] && size=0
  # 500MB cap per file
  if [ "$size" -gt 524288000 ]; then
    log "  skip oversize $src ($size)"
    return 1
  fi
  dest="${OUT_DIR}/${rel}"
  mkdir -p "$(dirname "$dest")"
  if cp "$src" "$dest" 2>/dev/null; then
    printf '%d|%s|%s|%s\n' "$size" "$cat" "$src" "$rel" >> "$MANIFEST_FILES"
    CUR_FILES=$((CUR_FILES + 1))
    CUR_BYTES=$((CUR_BYTES + size))
    return 0
  fi
  return 1
}

# capture_glob ROOT GLOB CATEGORY REL_PREFIX
capture_glob() {
  root="$1"; pat="$2"; cat="$3"; relprefix="$4"
  [ -d "$root" ] || return 0
  # POSIX find; ignore errors silently
  find "$root" -type f -name "$pat" 2>/dev/null | while IFS= read -r f; do
    rel="${relprefix}/${f#${root}/}"
    capture_file "$f" "$rel" "$cat" >/dev/null
  done
}

# write_text REL CATEGORY  (reads from stdin)
write_text() {
  rel="$1"; cat="$2"
  dest="${OUT_DIR}/${rel}"
  mkdir -p "$(dirname "$dest")"
  cat > "$dest"
  size=$(wc -c < "$dest" 2>/dev/null | tr -d ' ' || echo 0)
  [ -z "$size" ] && size=0
  printf '%d|%s|%s|%s\n' "$size" "$cat" "$dest" "$rel" >> "$MANIFEST_FILES"
  CUR_FILES=$((CUR_FILES + 1))
  CUR_BYTES=$((CUR_BYTES + size))
}

# run_capture REL CATEGORY -- CMD ARGS...
run_capture() {
  rel="$1"; cat="$2"; shift 2
  [ "$1" = "--" ] && shift
  dest="${OUT_DIR}/${rel}"
  mkdir -p "$(dirname "$dest")"
  if "$@" >"$dest" 2>>"$LOG"; then
    size=$(wc -c < "$dest" 2>/dev/null | tr -d ' ' || echo 0)
    [ -z "$size" ] && size=0
    printf '%d|%s|%s|%s\n' "$size" "$cat" "cmd:$*" "$rel" >> "$MANIFEST_FILES"
    CUR_FILES=$((CUR_FILES + 1))
    CUR_BYTES=$((CUR_BYTES + size))
  else
    rm -f "$dest" 2>/dev/null
  fi
}

# ---- collectors ------------------------------------------------------------

collect_system_info() {
  start_collector "SystemInfo"
  run_capture "live/uname.txt"            "system_info" -- uname -a
  run_capture "live/vmware_version.txt"   "system_info" -- vmware -lv
  run_capture "live/esxcli_system_version.txt" "system_info" -- esxcli system version get
  run_capture "live/esxcli_hostname.txt"  "system_info" -- esxcli system hostname get
  run_capture "live/esxcli_uuid.txt"      "system_info" -- esxcli system uuid get
  run_capture "live/esxcli_welcomemessage.txt" "system_info" -- esxcli system welcomemsg get
  run_capture "live/esxcli_settings_advanced.txt" "system_info" -- esxcli system settings advanced list
  run_capture "live/esxcli_settings_kernel.txt"  "system_info" -- esxcli system settings kernel list
  run_capture "live/esxcli_module_list.txt" "system_info" -- esxcli system module list
  run_capture "live/esxcli_boot_device.txt" "system_info" -- esxcli system boot device get
  run_capture "live/esxcli_maintenancemode.txt" "system_info" -- esxcli system maintenanceMode get
  run_capture "live/esxcli_secureboot.txt" "system_info" -- esxcli system settings encryption get
  run_capture "live/uptime.txt"            "system_info" -- uptime
  run_capture "live/date_utc.txt"          "system_info" -- date -u
  run_capture "live/timekeeping.txt"       "system_info" -- esxcli system time get
  end_collector
}

collect_users_auth() {
  start_collector "UsersAuth"
  capture_file "/etc/passwd"        "artifacts/auth/passwd"        "users"
  capture_file "/etc/shadow"        "artifacts/auth/shadow"        "users"
  capture_file "/etc/group"         "artifacts/auth/group"         "users"
  capture_file "/etc/sudoers"       "artifacts/auth/sudoers"       "users"
  capture_file "/etc/security/access.conf" "artifacts/auth/access.conf" "users"
  capture_file "/etc/pam.d/passwd"  "artifacts/auth/pam.d_passwd"  "users"
  capture_file "/etc/pam.d/system-auth-generic" "artifacts/auth/pam.d_system-auth-generic" "users"
  capture_file "/etc/sssd/sssd.conf" "artifacts/auth/sssd.conf"    "users"
  capture_glob "/etc/sudoers.d" "*"   "users" "artifacts/auth/sudoers.d"
  capture_glob "/etc/pam.d"     "*"   "users" "artifacts/auth/pam.d"
  capture_glob "/etc/security"  "*"   "users" "artifacts/auth/security"
  run_capture "live/account_list.txt" "users" -- esxcli system account list
  run_capture "live/permission_list.txt" "users" -- esxcli system permission list
  run_capture "live/lockdown.txt"        "users" -- vim-cmd hostsvc/lockdown_is_enabled
  run_capture "live/who.txt"             "users" -- who
  run_capture "live/last.txt"            "users" -- last
  end_collector
}

collect_logs() {
  start_collector "SystemLogs"
  # ESXi log directory.
  capture_glob "/var/log" "*.log"    "esxi_logs" "artifacts/var_log"
  capture_glob "/var/log" "*.log.*"  "esxi_logs" "artifacts/var_log"
  capture_glob "/var/log" "*.gz"     "esxi_logs" "artifacts/var_log"
  capture_glob "/var/log" "*"        "esxi_logs" "artifacts/var_log"
  # Useful symlink targets.
  capture_file "/var/run/log/auth.log"     "artifacts/var_log/auth.log"     "esxi_logs"
  capture_file "/var/run/log/hostd.log"    "artifacts/var_log/hostd.log"    "esxi_logs"
  capture_file "/var/run/log/vpxa.log"     "artifacts/var_log/vpxa.log"     "esxi_logs"
  capture_file "/var/run/log/vmkernel.log" "artifacts/var_log/vmkernel.log" "esxi_logs"
  capture_file "/var/run/log/vmkwarning.log" "artifacts/var_log/vmkwarning.log" "esxi_logs"
  capture_file "/var/run/log/shell.log"    "artifacts/var_log/shell.log"    "esxi_logs"
  capture_file "/var/run/log/syslog.log"   "artifacts/var_log/syslog.log"   "esxi_logs"
  capture_file "/var/run/log/usb.log"      "artifacts/var_log/usb.log"      "esxi_logs"
  capture_file "/var/run/log/storagerm.log" "artifacts/var_log/storagerm.log" "esxi_logs"

  run_capture "live/esxcli_syslog_config.txt" "esxi_logs" -- esxcli system syslog config get
  run_capture "live/esxcli_syslog_logger.txt" "esxi_logs" -- esxcli system syslog config logger list
  run_capture "live/esxcli_coredump_partition.txt" "esxi_logs" -- esxcli system coredump partition list
  run_capture "live/esxcli_coredump_file.txt"      "esxi_logs" -- esxcli system coredump file list
  end_collector
}

collect_shell_history() {
  start_collector "ShellHistory"
  for h in /root /home/*; do
    [ -d "$h" ] || continue
    user="$(basename "$h")"
    for f in .ash_history .bash_history .sh_history .history .lesshst .viminfo; do
      capture_file "$h/$f" "artifacts/shell_history/$user/$f" "shell_history"
    done
  done
  end_collector
}

collect_ssh() {
  start_collector "SSH"
  capture_file "/etc/ssh/sshd_config" "artifacts/ssh/sshd_config" "ssh"
  capture_file "/etc/ssh/ssh_config"  "artifacts/ssh/ssh_config"  "ssh"
  capture_glob "/etc/ssh" "*"         "ssh" "artifacts/ssh"
  for h in /root /home/*; do
    [ -d "$h/.ssh" ] || continue
    user="$(basename "$h")"
    for f in authorized_keys known_hosts config id_rsa.pub id_ed25519.pub id_ecdsa.pub; do
      capture_file "$h/.ssh/$f" "artifacts/ssh/users/$user/$f" "ssh"
    done
  done
  run_capture "live/esxcli_ssh_config.txt" "ssh" -- esxcli system ssh server config list
  run_capture "live/esxcli_services_list.txt" "ssh" -- esxcli network firewall ruleset list
  end_collector
}

collect_network() {
  start_collector "Network"
  capture_file "/etc/hosts"       "artifacts/network/hosts"       "network"
  capture_file "/etc/resolv.conf" "artifacts/network/resolv.conf" "network"
  capture_file "/etc/services"    "artifacts/network/services"    "network"

  run_capture "live/esxcli_ip_interface.txt"  "network" -- esxcli network ip interface list
  run_capture "live/esxcli_ip_interface_ipv4.txt" "network" -- esxcli network ip interface ipv4 get
  run_capture "live/esxcli_ip_route_v4.txt"   "network" -- esxcli network ip route ipv4 list
  run_capture "live/esxcli_ip_route_v6.txt"   "network" -- esxcli network ip route ipv6 list
  run_capture "live/esxcli_ip_dns_server.txt" "network" -- esxcli network ip dns server list
  run_capture "live/esxcli_ip_dns_search.txt" "network" -- esxcli network ip dns search list
  run_capture "live/esxcli_vswitch.txt"       "network" -- esxcli network vswitch standard list
  run_capture "live/esxcli_vswitch_dvs.txt"   "network" -- esxcli network vswitch dvs vmware list
  run_capture "live/esxcli_portgroup.txt"     "network" -- esxcli network vswitch standard portgroup list
  run_capture "live/esxcli_nic.txt"           "network" -- esxcli network nic list
  run_capture "live/esxcli_vmnic_stats.txt"   "network" -- esxcli network nic stats list
  run_capture "live/esxcli_vmkernel_nic.txt"  "network" -- esxcli network ip interface list
  run_capture "live/esxcli_neighbor_v4.txt"   "network" -- esxcli network ip neighbor list
  run_capture "live/esxcli_neighbor_v6.txt"   "network" -- esxcli network ip neighbor list -V 6
  run_capture "live/esxcli_connection.txt"    "network" -- esxcli network ip connection list
  run_capture "live/esxcli_arp.txt"           "network" -- esxcli network ip neighbor list
  run_capture "live/netstat.txt"              "network" -- esxcli network ip connection list
  run_capture "live/esxcfg-route.txt"         "network" -- esxcfg-route -l
  end_collector
}

collect_firewall() {
  start_collector "Firewall"
  run_capture "live/firewall_get.txt"        "firewall" -- esxcli network firewall get
  run_capture "live/firewall_ruleset_list.txt" "firewall" -- esxcli network firewall ruleset list
  run_capture "live/firewall_ruleset_rule_list.txt" "firewall" -- esxcli network firewall ruleset rule list
  run_capture "live/firewall_ruleset_allowedip.txt" "firewall" -- esxcli network firewall ruleset allowedip list
  capture_glob "/etc/vmware/firewall" "*.xml" "firewall" "artifacts/firewall"
  capture_file "/etc/vmware/service.xml" "artifacts/firewall/service.xml" "firewall"
  end_collector
}

collect_storage() {
  start_collector "Storage"
  run_capture "live/storage_filesystem.txt"  "storage" -- esxcli storage filesystem list
  run_capture "live/storage_vmfs_extent.txt" "storage" -- esxcli storage vmfs extent list
  run_capture "live/storage_core_device.txt" "storage" -- esxcli storage core device list
  run_capture "live/storage_core_path.txt"   "storage" -- esxcli storage core path list
  run_capture "live/storage_core_adapter.txt" "storage" -- esxcli storage core adapter list
  run_capture "live/storage_iscsi_adapter.txt" "storage" -- esxcli iscsi adapter list
  run_capture "live/storage_nfs.txt"         "storage" -- esxcli storage nfs list
  run_capture "live/storage_nfs41.txt"       "storage" -- esxcli storage nfs41 list
  run_capture "live/storage_vsan_health.txt" "storage" -- esxcli vsan cluster get
  run_capture "live/storage_vvol.txt"        "storage" -- esxcli storage vvol storagecontainer list
  run_capture "live/df_h.txt"                "storage" -- df -h
  run_capture "live/mount.txt"               "storage" -- mount
  end_collector
}

collect_vms() {
  start_collector "VMs"
  run_capture "live/vmlist.txt"              "vms" -- vim-cmd vmsvc/getallvms
  # Per-VM detail: power state, summary, snapshot tree, vmx file.
  for vmid in $(vim-cmd vmsvc/getallvms 2>/dev/null | awk 'NR>1 {print $1}' | grep -E '^[0-9]+$'); do
    run_capture "live/vms/${vmid}/power.txt"      "vms" -- vim-cmd vmsvc/power.getstate "$vmid"
    run_capture "live/vms/${vmid}/get.summary.txt" "vms" -- vim-cmd vmsvc/get.summary "$vmid"
    run_capture "live/vms/${vmid}/get.config.txt"  "vms" -- vim-cmd vmsvc/get.config "$vmid"
    run_capture "live/vms/${vmid}/get.guestinfo.txt" "vms" -- vim-cmd vmsvc/get.guest "$vmid"
    run_capture "live/vms/${vmid}/get.runtime.txt" "vms" -- vim-cmd vmsvc/get.runtime "$vmid"
    run_capture "live/vms/${vmid}/snapshot.tree.txt" "vms" -- vim-cmd vmsvc/get.snapshotinfo "$vmid"
    run_capture "live/vms/${vmid}/devices.txt"     "vms" -- vim-cmd vmsvc/device.getdevices "$vmid"
  done
  # Capture .vmx and .vmdk metadata (small, descriptors only) for every registered VM.
  for vmx in $(vim-cmd vmsvc/getallvms 2>/dev/null | awk 'NR>1 {for (i=4; i<=NF; i++) printf "%s ", $i; print ""}' | grep -E '\.vmx'); do
    [ -f "$vmx" ] || continue
    base="$(dirname "$vmx")"
    name="$(basename "$vmx")"
    capture_file "$vmx" "artifacts/vms/${name}.vmx" "vms"
    # Also grab co-located .vmsd, .nvram, .log
    capture_glob "$base" "*.vmsd" "vms" "artifacts/vms"
    capture_glob "$base" "*.nvram" "vms" "artifacts/vms"
    capture_glob "$base" "vmware*.log" "vms" "artifacts/vms"
  done
  run_capture "live/vmkfstools_extent.txt"   "vms" -- vmkfstools -P /vmfs/volumes
  end_collector
}

collect_processes() {
  start_collector "Processes"
  run_capture "live/process_list.txt" "processes" -- esxcli system process list
  run_capture "live/ps_world.txt"     "processes" -- ps -Pwwc
  run_capture "live/esxtop_b.txt"     "processes" -- esxtop -b -n 1
  run_capture "live/lsof.txt"         "processes" -- lsof
  run_capture "live/vsi_meminfo.txt"  "processes" -- vsish -e get /memory/comprehensive
  end_collector
}

collect_modules() {
  start_collector "KernelModules"
  run_capture "live/module_list.txt"   "modules" -- esxcli system module list
  run_capture "live/vmkmod_loaded.txt" "modules" -- esxcli software vib list
  run_capture "live/vibs_acceptance.txt" "modules" -- esxcli software acceptance get
  run_capture "live/vibs_signature.txt"  "modules" -- esxcli software vib signature verify
  run_capture "live/profile_get.txt"     "modules" -- esxcli software profile get
  end_collector
}

collect_security() {
  start_collector "Security"
  run_capture "live/secureboot.txt"     "security" -- esxcli system settings encryption get
  run_capture "live/tpm.txt"            "security" -- esxcli hardware trustedboot get
  run_capture "live/keystore.txt"       "security" -- esxcli system security keypersistence get
  run_capture "live/certificates_machine.txt" "security" -- /usr/lib/vmware/openssl/bin/openssl x509 -in /etc/vmware/ssl/rui.crt -text -noout
  capture_file "/etc/vmware/ssl/rui.crt" "artifacts/security/rui.crt" "security"
  capture_file "/etc/vmware/ssl/castore.pem" "artifacts/security/castore.pem" "security"
  capture_glob "/etc/vmware/ssl" "*"     "security" "artifacts/security/ssl"
  capture_glob "/etc/vmware-vpx/docRoot/certs" "*" "security" "artifacts/security/vpx_certs"
  end_collector
}

collect_config() {
  start_collector "Config"
  capture_file "/etc/vmware/esx.conf"     "artifacts/config/esx.conf"     "config"
  capture_file "/etc/vmware/hostd/config.xml" "artifacts/config/hostd_config.xml" "config"
  capture_file "/etc/vmware/vpxa/vpxa.cfg" "artifacts/config/vpxa.cfg"    "config"
  capture_file "/etc/vmware/snmp.xml"     "artifacts/config/snmp.xml"     "config"
  capture_file "/etc/inetd.conf"          "artifacts/config/inetd.conf"   "config"
  capture_file "/etc/profile"             "artifacts/config/profile"      "config"
  capture_file "/etc/rc.local.d/local.sh" "artifacts/config/rc.local.sh"  "config"
  capture_glob "/etc/rc.local.d" "*"      "config" "artifacts/config/rc.local.d"
  capture_glob "/bootbank" "boot.cfg"     "config" "artifacts/config"
  capture_glob "/etc/vmware/welcome*"     "*" "config" "artifacts/config"
  end_collector
}

collect_persistence() {
  start_collector "Persistence"
  capture_glob "/etc/init.d" "*"             "persistence" "artifacts/persistence/init.d"
  capture_glob "/etc/cron.d" "*"             "persistence" "artifacts/persistence/cron.d"
  capture_glob "/var/spool/cron/crontabs" "*" "persistence" "artifacts/persistence/crontabs"
  capture_file "/etc/crontab"                "artifacts/persistence/crontab" "persistence"
  capture_file "/etc/rc.d/rc.local"          "artifacts/persistence/rc.local" "persistence"
  capture_file "/etc/rc.local.d/local.sh"    "artifacts/persistence/local.sh" "persistence"
  capture_file "/etc/profile"                "artifacts/persistence/profile" "persistence"
  capture_file "/.bashrc"                    "artifacts/persistence/bashrc"  "persistence"
  capture_file "/.profile"                   "artifacts/persistence/profile_root" "persistence"
  end_collector
}

collect_hardware() {
  start_collector "Hardware"
  run_capture "live/hardware_cpu.txt"     "hardware" -- esxcli hardware cpu list
  run_capture "live/hardware_memory.txt"  "hardware" -- esxcli hardware memory get
  run_capture "live/hardware_pci.txt"     "hardware" -- esxcli hardware pci list
  run_capture "live/hardware_clock.txt"   "hardware" -- esxcli hardware clock get
  run_capture "live/hardware_platform.txt" "hardware" -- esxcli hardware platform get
  run_capture "live/hardware_smbios.txt"  "hardware" -- smbiosDump
  run_capture "live/hardware_lspci.txt"   "hardware" -- lspci -p
  run_capture "live/hardware_usb.txt"     "hardware" -- esxcli hardware usb passthrough device list
  end_collector
}

collect_software() {
  start_collector "Software"
  run_capture "live/software_vib_list.txt" "software" -- esxcli software vib list
  run_capture "live/software_vib_get_all.txt" "software" -- esxcli software vib get
  run_capture "live/software_profile.txt" "software" -- esxcli software profile get
  run_capture "live/software_baseimage.txt" "software" -- esxcli software baseimage get
  run_capture "live/software_baseimage_components.txt" "software" -- esxcli software baseimage component list
  end_collector
}

collect_memory_artifacts() {
  start_collector "MemoryArtifacts"
  if [ "$INCLUDE_MEMORY" = "0" ]; then
    log "  memory artifacts skipped (use --include-memory)"
    end_collector "skipped (no --include-memory)"
    return 0
  fi
  for f in /var/core/* /vmkernel-zdump* /vmfs/volumes/datastore1/vmkernel-zdump*; do
    [ -f "$f" ] || continue
    capture_file "$f" "artifacts/memory/$(basename "$f")" "memory"
  done
  run_capture "live/coredump_active_partition.txt" "memory" -- esxcli system coredump partition get
  run_capture "live/coredump_active_file.txt"      "memory" -- esxcli system coredump file get
  end_collector
}

# ---- run -------------------------------------------------------------------

START_TS="$(date +%s 2>/dev/null || echo 0)"

run_step() {
  name="$1"; shift
  if skipped "$name"; then
    log "[skip] $name"
    return 0
  fi
  "$@"
}

run_step SystemInfo       collect_system_info
run_step UsersAuth        collect_users_auth
run_step SystemLogs       collect_logs
run_step ShellHistory     collect_shell_history
run_step SSH              collect_ssh
run_step Network          collect_network
run_step Firewall         collect_firewall
run_step Storage          collect_storage
run_step VMs              collect_vms
run_step Processes        collect_processes
run_step KernelModules    collect_modules
run_step Security         collect_security
run_step Config           collect_config
run_step Persistence      collect_persistence
run_step Hardware         collect_hardware
run_step Software         collect_software
run_step MemoryArtifacts  collect_memory_artifacts

END_TS="$(date +%s 2>/dev/null || echo 0)"
DURATION=$((END_TS - START_TS))

# ---- manifest --------------------------------------------------------------

OS_VERSION="$(esxcli system version get 2>/dev/null | awk -F': ' '/Product/ {print $2}')"
[ -z "$OS_VERSION" ] && OS_VERSION="ESXi"

MANIFEST="${OUT_DIR}/manifest.json"

{
  printf '{\n'
  printf '  "collector_version": "%s",\n' "$VERSION"
  printf '  "platform": "esxi",\n'
  printf '  "hostname": "%s",\n' "$HOSTNAME"
  printf '  "os_version": "%s",\n' "$OS_VERSION"
  printf '  "domain": "",\n'
  printf '  "collection_timestamp": "%s",\n' "$TS_RFC"
  printf '  "collection_duration_seconds": %d,\n' "$DURATION"
  printf '  "user_profiles": [],\n'

  # Totals
  TF=$(wc -l < "$MANIFEST_FILES" | tr -d ' ')
  TB=$(awk -F'|' '{s+=$1} END {printf "%d", s+0}' "$MANIFEST_FILES")
  printf '  "total_files": %d,\n' "$TF"
  printf '  "total_bytes": %d,\n' "$TB"

  # Collector results
  printf '  "collector_results": [\n'
  first=1
  while IFS='|' read -r cname cf cb cms cerr; do
    [ -z "$cname" ] && continue
    if [ "$first" -eq 0 ]; then printf ',\n'; fi
    first=0
    # Escape any quotes in cerr.
    cerr_esc=$(printf '%s' "$cerr" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '    {"name": "%s", "files_collected": %d, "bytes_collected": %d, "elapsed_ms": %d, "error": "%s"}' \
      "$cname" "$cf" "$cb" "$cms" "$cerr_esc"
  done < "$RESULTS"
  printf '\n  ],\n'

  # Files
  printf '  "files": [\n'
  first=1
  while IFS='|' read -r sz cat orig rel; do
    [ -z "$rel" ] && continue
    if [ "$first" -eq 0 ]; then printf ',\n'; fi
    first=0
    orig_esc=$(printf '%s' "$orig" | sed 's/\\/\\\\/g; s/"/\\"/g')
    rel_esc=$(printf '%s' "$rel" | sed 's/\\/\\\\/g; s/"/\\"/g')
    cat_esc=$(printf '%s' "$cat" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '    {"original_path": "%s", "relative_path": "%s", "category": "%s", "size": %d}' \
      "$orig_esc" "$rel_esc" "$cat_esc" "$sz"
  done < "$MANIFEST_FILES"
  printf '\n  ]\n'
  printf '}\n'
} > "$MANIFEST"

# ---- archive ---------------------------------------------------------------

ARCHIVE="${OUTPUT_BASE}/${COLLECTION_NAME}.tar.gz"
( cd "$OUTPUT_BASE" && tar czf "$ARCHIVE" "$COLLECTION_NAME" )

if [ -f "$ARCHIVE" ]; then
  SIZE=$(wc -c < "$ARCHIVE" 2>/dev/null | tr -d ' ')
  log "[+] Collection archive: $ARCHIVE ($SIZE bytes)"
  rm -rf "$OUT_DIR"
else
  log "[!] Failed to create archive at $ARCHIVE"
  exit 1
fi
