using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class OsConfigCollector : ICollector
{
    public string Name => "OsConfig";
    public string Description => "OS configuration: firewall, UAC, audit policy, RDP, Windows Update, network settings";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        var destDir = Path.Combine(context.OutputDir, "live");
        Directory.CreateDirectory(destDir);
        var timestamp = context.CollectionTime.ToUniversalTime().ToString("o");

        var settings = new List<OsConfigSetting>();

        CollectUacSettings(settings, timestamp);
        CollectFirewallSettings(settings, timestamp);
        CollectRdpSettings(settings, timestamp);
        CollectWindowsUpdateSettings(settings, timestamp);
        CollectNetworkProfiles(settings, timestamp);
        CollectAuditPolicy(settings, timestamp);
        CollectPowerShellPolicy(settings, timestamp);
        CollectDefenderSettings(settings, timestamp);
        CollectBitLockerStatus(settings, timestamp);

        var dest = Path.Combine(destDir, "os_config.json");
        File.WriteAllText(dest, JsonSerializer.Serialize(settings, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        }));

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = settings.Count,
            BytesCollected = new FileInfo(dest).Length,
            Elapsed = sw.Elapsed
        };
    }

    private static void CollectUacSettings(List<OsConfigSetting> settings, string timestamp)
    {
        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "UAC", settings, timestamp,
            "EnableLUA", "ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorUser",
            "PromptOnSecureDesktop", "FilterAdministratorToken");
    }

    private static void CollectFirewallSettings(List<OsConfigSetting> settings, string timestamp)
    {
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            ReadRegValues(Registry.LocalMachine,
                $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}",
                $"Firewall-{profile}", settings, timestamp,
                "EnableFirewall", "DisableNotifications", "DefaultInboundAction", "DefaultOutboundAction");
        }
    }

    private static void CollectRdpSettings(List<OsConfigSetting> settings, string timestamp)
    {
        ReadRegValues(Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "RDP", settings, timestamp,
            "fDenyTSConnections", "fSingleSessionPerUser");

        ReadRegValues(Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "RDP-Security", settings, timestamp,
            "UserAuthentication", "SecurityLayer", "MinEncryptionLevel");
    }

    private static void CollectWindowsUpdateSettings(List<OsConfigSetting> settings, string timestamp)
    {
        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "WindowsUpdate", settings, timestamp,
            "NoAutoUpdate", "AUOptions", "ScheduledInstallDay", "ScheduledInstallTime");

        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
            "WindowsUpdate-State", settings, timestamp,
            "AUState", "IsOOBEComplete");
    }

    private static void CollectNetworkProfiles(List<OsConfigSetting> settings, string timestamp)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles");
            if (key == null) return;

            foreach (var profileGuid in key.GetSubKeyNames())
            {
                using var profile = key.OpenSubKey(profileGuid);
                if (profile == null) continue;

                var name = profile.GetValue("ProfileName")?.ToString() ?? "";
                var category = profile.GetValue("Category");
                var managed = profile.GetValue("Managed");

                settings.Add(new OsConfigSetting
                {
                    Category = "NetworkProfile",
                    Name = name,
                    Value = $"Category={category}, Managed={managed}",
                    Detail = profileGuid,
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch { }
    }

    private static void CollectAuditPolicy(List<OsConfigSetting> settings, string timestamp)
    {
        try
        {
            var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "auditpol",
                Arguments = "/get /category:*",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            });
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit(10_000);

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("System Audit") ||
                    trimmed.StartsWith("Category") || !trimmed.Contains("  "))
                    continue;

                var parts = System.Text.RegularExpressions.Regex.Split(trimmed, @"\s{2,}");
                if (parts.Length >= 2)
                {
                    settings.Add(new OsConfigSetting
                    {
                        Category = "AuditPolicy",
                        Name = parts[0].Trim(),
                        Value = parts[^1].Trim(),
                        CollectionTimestamp = timestamp
                    });
                }
            }
        }
        catch { }
    }

    private static void CollectPowerShellPolicy(List<OsConfigSetting> settings, string timestamp)
    {
        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
            "PowerShell", settings, timestamp,
            "ExecutionPolicy");

        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\PowerShell",
            "PowerShell-Policy", settings, timestamp,
            "EnableScripts", "ExecutionPolicy", "EnableModuleLogging", "EnableScriptBlockLogging");

        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "PowerShell-ScriptBlockLogging", settings, timestamp,
            "EnableScriptBlockLogging", "EnableScriptBlockInvocationLogging");
    }

    private static void CollectDefenderSettings(List<OsConfigSetting> settings, string timestamp)
    {
        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows Defender",
            "Defender", settings, timestamp,
            "DisableAntiSpyware", "DisableAntiVirus", "ProductStatus");

        ReadRegValues(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "Defender-RealTime", settings, timestamp,
            "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
            "DisableOnAccessProtection", "DisableScanOnRealtimeEnable");

        // Exclusions
        foreach (var exType in new[] { "Paths", "Extensions", "Processes" })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows Defender\Exclusions\{exType}");
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                {
                    settings.Add(new OsConfigSetting
                    {
                        Category = $"Defender-Exclusion-{exType}",
                        Name = name,
                        Value = key.GetValue(name)?.ToString() ?? "",
                        CollectionTimestamp = timestamp
                    });
                }
            }
            catch { }
        }
    }

    private static void CollectBitLockerStatus(List<OsConfigSetting> settings, string timestamp)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                "SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume");
            foreach (var obj in searcher.Get())
            {
                settings.Add(new OsConfigSetting
                {
                    Category = "BitLocker",
                    Name = obj["DriveLetter"]?.ToString() ?? "",
                    Value = $"Protection={obj["ProtectionStatus"]}, Conversion={obj["ConversionStatus"]}",
                    CollectionTimestamp = timestamp
                });
            }
        }
        catch { }
    }

    private static void ReadRegValues(RegistryKey root, string path, string category,
        List<OsConfigSetting> settings, string timestamp, params string[] valueNames)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key == null) return;

            foreach (var name in valueNames)
            {
                var value = key.GetValue(name);
                if (value != null)
                {
                    settings.Add(new OsConfigSetting
                    {
                        Category = category,
                        Name = name,
                        Value = value.ToString() ?? "",
                        CollectionTimestamp = timestamp
                    });
                }
            }
        }
        catch { }
    }

    private class OsConfigSetting
    {
        [JsonPropertyName("category")] public string Category { get; set; } = "";
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("value")] public string Value { get; set; } = "";
        [JsonPropertyName("detail")] public string? Detail { get; set; }
        [JsonPropertyName("collection_timestamp")] public string CollectionTimestamp { get; set; } = "";
    }
}
