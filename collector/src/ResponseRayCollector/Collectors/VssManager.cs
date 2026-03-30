using System.Diagnostics;
using System.Text.RegularExpressions;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

public class VssManager : IDisposable
{
    private string? _shadowId;
    private string? _shadowPath;
    private bool _disposed;

    public string? ShadowPath => _shadowPath;

    public bool CreateSnapshot(string volume = "C:\\")
    {
        ConsoleOutput.Info("Creating Volume Shadow Copy...");

        try
        {
            var result = RunProcess("wmic", $"shadowcopy call create Volume=\"{volume}\"");
            if (result.ExitCode != 0)
            {
                ConsoleOutput.Error($"VSS creation failed (exit {result.ExitCode}): {result.StdErr}");
                return false;
            }

            // Parse shadow ID from output: ShadowID = "{guid}"
            var idMatch = Regex.Match(result.StdOut, @"ShadowID\s*=\s*""(\{[^}]+\})""", RegexOptions.IgnoreCase);
            if (!idMatch.Success)
            {
                // Fallback: list shadows and take the newest one
                var listResult = RunProcess("vssadmin", "list shadows");
                var matches = Regex.Matches(listResult.StdOut,
                    @"Shadow Copy ID:\s*(\{[^}]+\}).*?Shadow Copy Volume:\s*(\\\\\?\\[^\r\n]+)",
                    RegexOptions.Singleline);

                if (matches.Count == 0)
                {
                    ConsoleOutput.Error("Could not find VSS shadow copy ID");
                    return false;
                }

                var last = matches[^1];
                _shadowId = last.Groups[1].Value;
                _shadowPath = last.Groups[2].Value.TrimEnd('\\') + "\\";
            }
            else
            {
                _shadowId = idMatch.Groups[1].Value;

                // Get the device path for the shadow
                var listResult = RunProcess("vssadmin", "list shadows");
                var pathMatch = Regex.Match(listResult.StdOut,
                    Regex.Escape(_shadowId) + @".*?Shadow Copy Volume:\s*(\\\\\?\\[^\r\n]+)",
                    RegexOptions.Singleline | RegexOptions.IgnoreCase);

                if (pathMatch.Success)
                {
                    _shadowPath = pathMatch.Groups[1].Value.TrimEnd('\\') + "\\";
                }
                else
                {
                    // Try GLOBALROOT path format
                    var globalMatch = Regex.Match(listResult.StdOut,
                        Regex.Escape(_shadowId) + @".*?(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)\\?",
                        RegexOptions.Singleline | RegexOptions.IgnoreCase);
                    if (globalMatch.Success)
                        _shadowPath = globalMatch.Groups[1].Value + "\\";
                }
            }

            if (_shadowPath != null)
            {
                ConsoleOutput.Info($"VSS snapshot created: {_shadowId}");
                ConsoleOutput.Status($"Shadow path: {_shadowPath}");
                return true;
            }

            ConsoleOutput.Error("VSS snapshot created but could not determine device path");
            return false;
        }
        catch (Exception ex)
        {
            ConsoleOutput.Error($"VSS creation exception: {ex.Message}");
            return false;
        }
    }

    public void DeleteSnapshot()
    {
        if (_shadowId == null) return;

        try
        {
            ConsoleOutput.Info($"Deleting VSS snapshot {_shadowId}...");
            RunProcess("vssadmin", $"delete shadows /Shadow={_shadowId} /Quiet");
            _shadowId = null;
            _shadowPath = null;
        }
        catch (Exception ex)
        {
            ConsoleOutput.Warning($"Failed to delete VSS snapshot: {ex.Message}");
        }
    }

    private static (int ExitCode, string StdOut, string StdErr) RunProcess(string fileName, string args)
    {
        using var proc = new Process();
        proc.StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        proc.Start();
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(60_000);
        return (proc.ExitCode, stdout, stderr);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            DeleteSnapshot();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    ~VssManager() => Dispose();
}
