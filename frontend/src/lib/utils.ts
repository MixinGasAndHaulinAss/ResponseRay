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

export function timeAgo(dt: string): string {
  const seconds = Math.floor((Date.now() - new Date(dt).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export const EVENT_TYPE_LABELS: Record<string, string> = {
  account_created: 'Accounts',
  browser_history: 'Browser History',
  dhcp_event: 'DHCP',
  file_access: 'File Access',
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
  startup_item: 'Startup Items',
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
}

export const FINDING_COLORS: Record<string, string> = {
  bad: 'bg-red-500/20 text-red-400 border-red-500/30',
  suspicious: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  good: 'bg-green-500/20 text-green-400 border-green-500/30',
}
