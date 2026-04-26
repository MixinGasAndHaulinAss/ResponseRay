using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Collects log directories for ~50 forensically interesting third-party tools (remote support,
/// AV/EDR, communication, dev tools). The list is hard-coded but easy to extend.
/// </summary>
public class ApplicationLogsCollector : ICollector
{
    public string Name => "ApplicationLogs";
    public string Description => "Logs for remote-support tools, AV/EDR, comms, dev tools";

    private const long MaxFileSize = 200L * 1024 * 1024;

    private record AppEntry(string Label, string[] PathTemplates, string[] Extensions);

    /// <summary>
    /// Path templates support placeholders:
    ///   {ProgramData} - C:\ProgramData
    ///   {ProgramFiles} - C:\Program Files
    ///   {ProgramFilesX86} - C:\Program Files (x86)
    ///   {SystemDrive} - C:
    ///   {Windows} - C:\Windows
    ///   {AppData} - per-user AppData\Roaming
    ///   {LocalAppData} - per-user AppData\Local
    /// Per-user templates iterate every user profile.
    /// </summary>
    private static readonly AppEntry[] Apps =
    [
        // Remote support / RMM
        new("teamviewer", [@"{ProgramData}\TeamViewer", @"{LocalAppData}\TeamViewer"], [".log", ".txt"]),
        new("anydesk", [@"{ProgramData}\AnyDesk", @"{AppData}\AnyDesk"], [".trace", ".log", ".conf"]),
        new("splashtop", [@"{ProgramFiles}\Splashtop\Splashtop Remote\Server\log", @"{ProgramData}\Splashtop"], [".log", ".txt"]),
        new("logmein", [@"{ProgramData}\LogMeIn", @"{ProgramFiles(x86)}\LogMeIn"], [".log"]),
        new("connectwise", [@"{ProgramData}\ScreenConnect Client", @"{ProgramFiles(x86)}\ScreenConnect Client"], [".log", ".txt"]),
        new("connectwise_control", [@"{ProgramFiles(x86)}\ScreenConnect"], [".log", ".txt"]),
        new("bomgar_beyondtrust", [@"{ProgramData}\BeyondTrust", @"{ProgramFiles}\BeyondTrust"], [".log", ".txt"]),
        new("vnc", [@"{ProgramData}\RealVNC", @"{ProgramFiles}\RealVNC", @"{ProgramData}\TightVNC", @"{ProgramFiles}\TightVNC"], [".log", ".txt"]),
        new("supremo", [@"{LocalAppData}\Supremo"], [".log", ".txt"]),
        new("ammyy", [@"{ProgramData}\AMMYY"], [".log", ".txt"]),
        new("kaseya", [@"{ProgramData}\Kaseya", @"{ProgramFiles(x86)}\Kaseya"], [".log", ".txt"]),
        new("ninjarmm", [@"{ProgramData}\NinjaRMMAgent"], [".log", ".txt", ".db"]),
        new("datto", [@"{ProgramData}\CentraStage", @"{ProgramData}\Datto"], [".log", ".txt"]),
        new("atera", [@"{ProgramFiles}\ATERA Networks", @"{ProgramData}\ATERA Networks"], [".log", ".txt"]),
        new("solarwinds_rmm", [@"{ProgramData}\SolarWinds MSP", @"{ProgramFiles(x86)}\SolarWinds MSP"], [".log", ".txt"]),
        new("syncro", [@"{ProgramData}\SyncroMSP"], [".log", ".txt"]),
        new("level", [@"{ProgramData}\Level"], [".log", ".txt"]),

        // AV / EDR
        new("crowdstrike", [@"{ProgramData}\CrowdStrike", @"{Windows}\System32\drivers\CrowdStrike"], [".log", ".txt"]),
        new("sentinelone", [@"{ProgramData}\Sentinel", @"{ProgramFiles}\SentinelOne"], [".log", ".txt"]),
        new("sophos", [@"{ProgramData}\Sophos", @"{ProgramFiles}\Sophos"], [".log", ".txt"]),
        new("malwarebytes", [@"{ProgramData}\Malwarebytes", @"{ProgramFiles}\Malwarebytes"], [".log", ".txt"]),
        new("symantec", [@"{ProgramData}\Symantec", @"{ProgramFiles(x86)}\Symantec"], [".log", ".txt"]),
        new("trendmicro", [@"{ProgramData}\Trend Micro"], [".log", ".txt"]),
        new("eset", [@"{ProgramData}\ESET", @"{ProgramFiles}\ESET"], [".log", ".txt", ".dat"]),
        new("kaspersky", [@"{ProgramData}\Kaspersky Lab"], [".log", ".txt"]),
        new("bitdefender", [@"{ProgramData}\Bitdefender", @"{ProgramFiles}\Bitdefender"], [".log", ".txt"]),
        new("webroot", [@"{ProgramData}\WRData"], [".log", ".txt"]),
        new("carbonblack", [@"{ProgramData}\CarbonBlack", @"{ProgramFiles}\Confer"], [".log", ".txt"]),
        new("huntress", [@"{ProgramData}\Huntress", @"{ProgramFiles}\Huntress"], [".log", ".txt"]),

        // Communication / collaboration
        new("teams", [@"{LocalAppData}\Microsoft\Teams\logs.txt",
                      @"{LocalAppData}\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs"], [".txt", ".log"]),
        new("zoom", [@"{AppData}\Zoom\logs"], [".log", ".txt"]),
        new("slack", [@"{AppData}\Slack\logs"], [".log", ".txt"]),
        new("discord", [@"{AppData}\discord"], [".log", ".txt"]),
        new("webex", [@"{AppData}\Webex"], [".log", ".txt"]),
        new("gotomeeting", [@"{AppData}\LogMeIn", @"{AppData}\GoToMeeting"], [".log", ".txt"]),
        new("skype", [@"{AppData}\Microsoft\Skype for Desktop\logs"], [".log", ".txt"]),

        // Dev / sysadmin tools
        new("git", [@"{AppData}\Git"], [".log"]),
        new("docker", [@"{AppData}\Docker"], [".log", ".txt"]),
        new("vscode", [@"{AppData}\Code\logs"], [".log", ".txt"]),
        new("openssh", [@"{ProgramData}\ssh\logs"], [".log", ".txt"]),
        new("putty", [@"{AppData}\PuTTY"], [".log", ".reg"]),
        new("winscp", [@"{AppData}\WinSCP"], [".log", ".ini"]),
        new("rdp_files", [@"{Documents}"], [".rdp"]),
        new("powershell_profile", [@"{Documents}\WindowsPowerShell"], [".ps1", ".log"]),

        // Cloud sync / file share
        new("onedrive", [@"{LocalAppData}\Microsoft\OneDrive\logs"], [".log", ".odl"]),
        new("dropbox", [@"{AppData}\Dropbox"], [".log"]),
        new("googledrive", [@"{LocalAppData}\Google\DriveFS"], [".log", ".txt"]),
        new("box", [@"{LocalAppData}\Box\Box"], [".log", ".txt"]),
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        var systemContext = new Dictionary<string, string>
        {
            ["{ProgramData}"] = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            ["{ProgramFiles}"] = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ["{ProgramFiles(x86)}"] = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            ["{Windows}"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            ["{SystemDrive}"] = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 2),
        };

        foreach (var app in Apps)
        {
            foreach (var template in app.PathTemplates)
            {
                if (!template.Contains("{AppData}") && !template.Contains("{LocalAppData}") &&
                    !template.Contains("{Documents}"))
                {
                    var path = Substitute(template, systemContext);
                    CaptureFromPath(path, app, app.Label, context, ref count, ref bytes);
                }
                else
                {
                    foreach (var userDir in FileHelper.GetUserProfilePaths())
                    {
                        var username = Path.GetFileName(userDir)!;
                        var userContext = new Dictionary<string, string>(systemContext)
                        {
                            ["{AppData}"] = Path.Combine(userDir, "AppData", "Roaming"),
                            ["{LocalAppData}"] = Path.Combine(userDir, "AppData", "Local"),
                            ["{Documents}"] = Path.Combine(userDir, "Documents"),
                        };
                        var path = Substitute(template, userContext);
                        CaptureFromPath(path, app, $"{app.Label}/{username}", context, ref count, ref bytes);
                    }
                }
            }
        }

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = count,
            BytesCollected = bytes,
            Elapsed = sw.Elapsed
        };
    }

    private static string Substitute(string template, Dictionary<string, string> ctx)
    {
        var s = template;
        foreach (var (k, v) in ctx) s = s.Replace(k, v);
        return s;
    }

    private static void CaptureFromPath(string path, AppEntry app, string subdirLabel,
        CollectionContext context, ref int count, ref long bytes)
    {
        try
        {
            // Path may be a file or a directory.
            if (File.Exists(path))
            {
                var rel = Path.Combine("artifacts", "applogs", subdirLabel, Path.GetFileName(path));
                context.TryCaptureFile(path, rel, "application_logs", ref count, ref bytes);
                return;
            }

            if (!Directory.Exists(path)) return;

            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (app.Extensions.Length > 0 && !app.Extensions.Contains(ext)) continue;

                    var info = new FileInfo(file);
                    if (info.Length > MaxFileSize) continue;

                    var relInRoot = Path.GetRelativePath(path, file);
                    var rel = Path.Combine("artifacts", "applogs", subdirLabel, relInRoot);
                    context.TryCaptureFile(file, rel, "application_logs", ref count, ref bytes);
                }
                catch { }
            }
        }
        catch { }
    }
}
