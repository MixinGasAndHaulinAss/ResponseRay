using System.Diagnostics;
using Microsoft.Win32;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// On Domain Controllers, captures NTDS.dit and the supporting transaction logs. Skipped silently
/// on workstations where the file does not exist or AD DS isn't installed.
/// </summary>
public class NtdsCollector : ICollector
{
    public string Name => "NTDS";
    public string Description => "Active Directory database (NTDS.dit) and transaction logs (DC only)";

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        // Find NTDS path from registry
        string? ntdsPath = null;
        string? logPath = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\NTDS\Parameters");
            ntdsPath = key?.GetValue("DSA Database file") as string;
            logPath = key?.GetValue("Database log files path") as string;
        }
        catch { }

        // Default location
        ntdsPath ??= @"C:\Windows\NTDS\ntds.dit";
        logPath ??= @"C:\Windows\NTDS";

        var ntdsRel = Path.Combine("artifacts", "ntds", "ntds.dit");
        if (context.TryCaptureFile(ntdsPath, ntdsRel, "ntds", ref count, ref bytes))
        {
            ConsoleOutput.Status("  ntds.dit: captured");
        }

        if (Directory.Exists(logPath))
        {
            foreach (var file in Directory.EnumerateFiles(logPath, "edb*.log").Concat(
                         Directory.EnumerateFiles(logPath, "edb.chk")))
            {
                var rel = Path.Combine("artifacts", "ntds", Path.GetFileName(file));
                context.TryCaptureFile(file, rel, "ntds", ref count, ref bytes);
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
}
