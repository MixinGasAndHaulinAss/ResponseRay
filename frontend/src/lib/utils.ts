import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat().format(n)
}

export function formatDateTime(dt: string): string {
  try {
    return new Date(dt).toLocaleString()
  } catch {
    return dt
  }
}

export function formatDateTimeShort(dt: string): string {
  try {
    const d = new Date(dt)
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  } catch {
    return dt
  }
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`
}

export function timeAgo(dt: string): string {
  const seconds = Math.floor((Date.now() - new Date(dt).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export const EVENT_TYPE_LABELS: Record<string, string> = {
  // Cross-platform event types (work for Windows, macOS, Linux, ESXi)
  running_process: 'Running Processes',
  active_connection: 'Network Connections',
  shell_command: 'Shell History',
  ssh_authorized_key: 'SSH Authorized Keys',
  ssh_known_host: 'SSH Known Hosts',
  account_created: 'User Accounts',
  installed_program: 'Installed Programs',
  os_config: 'OS Configuration',
  firewall_rule: 'Firewall Rules',
  startup_item: 'Startup Items',
  file_access: 'File Access',

  // macOS-specific event types
  file_downloaded: 'Downloaded Files',
  tcc_grant: 'TCC Permissions',
  application_usage: 'Application Usage',
  application_focus: 'App Focus',
  app_intent: 'App Intent',
  app_activity: 'App Activity',
  web_usage: 'Web Usage',
  device_locked: 'Device Locked',
  device_unlocked: 'Device Unlocked',
  display_on: 'Display On',
  display_off: 'Display Off',
  battery_level: 'Battery Level',
  device_topic: 'Device Topic',
  os_log: 'Unified Log',
  web_history: 'Web History',
  web_download: 'Web Download',
  web_cookie: 'Web Cookie',
  web_login: 'Web Login',
  form_history: 'Form History',

  // Windows-specific event types
  browser_history: 'Browser History',
  dhcp_event: 'DHCP',
  file_deleted: 'Deleted Files',
  file_timeline: 'File Timeline (SI)',
  file_timeline_fn: 'File Timeline (FN)',
  lnk_target: 'LNK Shortcuts',
  network_connection: 'Network Connections',
  network_share: 'Network Shares',
  powershell_history: 'PowerShell History',
  process_execution: 'Process Execution',
  registry_amcache: 'Amcache',
  registry_bam: 'BAM Execution',
  registry_networklist: 'Network Profiles',
  registry_recentdocs: 'Recent Documents',
  registry_runmru: 'Run MRU',
  registry_service: 'Registry Services',
  registry_shellbag: 'ShellBags',
  registry_software: 'Installed Software',
  registry_typedurls: 'Typed URLs',
  registry_userassist: 'UserAssist',
  registry_winlogon: 'Winlogon',
  session_logon: 'Session Processes',
  srum_app_usage: 'SRUM App Usage',
  srum_network_connectivity: 'SRUM Network',
  windows_authentication: 'Authentication',
  windows_defender: 'Windows Defender',
  windows_dns: 'DNS',
  windows_event: 'Event Log',
  windows_logon: 'Logon Events',
  windows_powershell: 'PowerShell Scripts',
  windows_process: 'Process Creation',
  windows_rdp: 'RDP Sessions',
  windows_service: 'Service Events',
  windows_smb: 'SMB',
  windows_task: 'Scheduled Tasks',
  wmi_persistence: 'WMI Persistence',

  // Linux-specific event types
  journal_entry: 'Journal Entry',
  auth_log: 'Auth Log',
  syslog_entry: 'Syslog',
  logon_success: 'Logon Success',
  logon_failed: 'Logon Failed',
  logon_session: 'Logon Session',
  scheduled_task: 'Scheduled Tasks',
  kernel_module: 'Kernel Modules',
  suid_binary: 'SUID Binaries',
  sgid_binary: 'SGID Binaries',
  shared_memory: 'Shared Memory',
  mount_entry: 'Mounts',
  nfs_export: 'NFS Exports',
  docker_container: 'Docker Containers',
  docker_image: 'Docker Images',
  docker_network: 'Docker Networks',
  docker_volume: 'Docker Volumes',
  apt_history: 'APT History',
  yum_history: 'YUM History',
  dnf_history: 'DNF History',

  // ESXi-specific event types
  esxi_vm_event: 'VM Event',
  esxi_host_event: 'Host Event',
  esxi_process: 'ESXi Processes',
  esxi_network: 'ESXi Network',
  esxi_datastore: 'ESXi Datastores',
  esxi_firewall: 'ESXi Firewall',
}

export const FINDING_COLORS: Record<string, string> = {
  bad: 'bg-red-500/20 text-red-400 border-red-500/30',
  suspicious: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  good: 'bg-green-500/20 text-green-400 border-green-500/30',
}
