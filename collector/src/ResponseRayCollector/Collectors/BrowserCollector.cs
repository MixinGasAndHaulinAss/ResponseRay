using System.Diagnostics;
using ResponseRayCollector.Utils;

namespace ResponseRayCollector.Collectors;

/// <summary>
/// Collects browser forensic artifacts for every Chromium-derived browser plus Firefox plus IE/legacy
/// Edge. For each profile we copy: History, Cookies, Login Data, Web Data (forms/autofill),
/// Bookmarks, Top Sites, Network Action Predictor, Shortcuts, Favicons, Visited Links, and the
/// extension manifest.json files.
/// </summary>
public class BrowserCollector : ICollector
{
    public string Name => "Browser";
    public string Description => "Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi, Arc), Firefox, and IE/Edge legacy WebCacheV01";

    /// <summary>
    /// (DisplayName, RelativePathFromUserProfile) — Chromium-family browsers.
    /// </summary>
    private static readonly (string Browser, string RelPath)[] ChromiumBrowsers =
    [
        ("chrome", @"AppData\Local\Google\Chrome\User Data"),
        ("chrome_canary", @"AppData\Local\Google\Chrome SxS\User Data"),
        ("edge", @"AppData\Local\Microsoft\Edge\User Data"),
        ("edge_dev", @"AppData\Local\Microsoft\Edge Dev\User Data"),
        ("brave", @"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        ("opera", @"AppData\Roaming\Opera Software\Opera Stable"),
        ("opera_gx", @"AppData\Roaming\Opera Software\Opera GX Stable"),
        ("vivaldi", @"AppData\Local\Vivaldi\User Data"),
        ("arc", @"AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data"),
        ("yandex", @"AppData\Local\Yandex\YandexBrowser\User Data"),
        ("chromium", @"AppData\Local\Chromium\User Data"),
    ];

    /// <summary>
    /// Files inside a Chromium profile we want.
    /// </summary>
    private static readonly string[] ChromiumProfileFiles =
    [
        "History",
        "History-journal",
        "Cookies",
        "Login Data",
        "Login Data For Account",
        "Web Data",
        "Bookmarks",
        "Top Sites",
        "Network Action Predictor",
        "Shortcuts",
        "Favicons",
        "Visited Links",
        "Preferences",
        "Secure Preferences",
        "Last Session",
        "Last Tabs",
        "Current Session",
        "Current Tabs",
    ];

    /// <summary>
    /// Files inside a Firefox profile.
    /// </summary>
    private static readonly string[] FirefoxProfileFiles =
    [
        "places.sqlite",
        "places.sqlite-wal",
        "cookies.sqlite",
        "formhistory.sqlite",
        "downloads.sqlite",
        "permissions.sqlite",
        "logins.json",
        "key4.db",
        "signons.sqlite",
        "favicons.sqlite",
        "content-prefs.sqlite",
        "addons.json",
        "extensions.json",
        "prefs.js",
        "sessionstore.jsonlz4",
        "handlers.json",
    ];

    public CollectorResult Collect(CollectionContext context)
    {
        var sw = Stopwatch.StartNew();
        int count = 0;
        long bytes = 0;

        foreach (var userDir in FileHelper.GetUserProfilePaths())
        {
            var username = Path.GetFileName(userDir)!;

            foreach (var (browser, rel) in ChromiumBrowsers)
            {
                var browserDir = Path.Combine(userDir, rel);
                if (!Directory.Exists(browserDir)) continue;
                CollectChromiumBrowser(context, browserDir, username, browser, ref count, ref bytes);
            }

            CollectFirefox(context, userDir, username, ref count, ref bytes);
            CollectInternetExplorerLegacy(context, userDir, username, ref count, ref bytes);
        }

        return new CollectorResult
        {
            CollectorName = Name,
            FilesCollected = count,
            BytesCollected = bytes,
            Elapsed = sw.Elapsed
        };
    }

    private static void CollectChromiumBrowser(CollectionContext context, string browserDir,
        string username, string browser, ref int count, ref long bytes)
    {
        // Local State (browser-wide config)
        var localState = Path.Combine(browserDir, "Local State");
        if (File.Exists(localState))
        {
            var rel = Path.Combine("artifacts", "browser", browser, username, "Local State");
            context.TryCaptureFile(localState, rel, "browser", ref count, ref bytes);
        }

        // Each profile is a subdirectory containing History etc.
        IEnumerable<string> profiles;
        try { profiles = Directory.EnumerateDirectories(browserDir); }
        catch { return; }

        foreach (var profileDir in profiles)
        {
            var profileName = Path.GetFileName(profileDir);
            // Skip non-profile dirs
            if (profileName == "Crashpad" || profileName == "PnaclTranslationCache" ||
                profileName == "GrShaderCache" || profileName == "ShaderCache" ||
                profileName == "Subresource Filter" || profileName == "GraphiteDawnCache" ||
                profileName == "Safe Browsing" || profileName == "ZxcvbnData" ||
                profileName == "OnDeviceHeadSuggestModel" || profileName == "PKIMetadata") continue;

            // Heuristic: only consider folder a profile if it has a History or Preferences file
            if (!File.Exists(Path.Combine(profileDir, "History")) &&
                !File.Exists(Path.Combine(profileDir, "Preferences")))
            {
                continue;
            }

            foreach (var file in ChromiumProfileFiles)
            {
                var src = Path.Combine(profileDir, file);
                if (!File.Exists(src)) continue;
                var rel = Path.Combine("artifacts", "browser", browser, username, profileName, file);
                context.TryCaptureFile(src, rel, "browser", ref count, ref bytes);
            }

            // Extension manifests (one manifest.json per extension version)
            var extDir = Path.Combine(profileDir, "Extensions");
            if (Directory.Exists(extDir))
            {
                foreach (var manifest in Directory.EnumerateFiles(extDir, "manifest.json", SearchOption.AllDirectories))
                {
                    var relPath = Path.GetRelativePath(extDir, manifest);
                    var rel = Path.Combine("artifacts", "browser", browser, username, profileName, "Extensions", relPath);
                    context.TryCaptureFile(manifest, rel, "browser_extension", ref count, ref bytes);
                }
            }

            // Sessions / Tabs subdirs (recently closed tabs)
            var sessionsDir = Path.Combine(profileDir, "Sessions");
            if (Directory.Exists(sessionsDir))
            {
                foreach (var file in Directory.EnumerateFiles(sessionsDir))
                {
                    var rel = Path.Combine("artifacts", "browser", browser, username, profileName, "Sessions", Path.GetFileName(file));
                    context.TryCaptureFile(file, rel, "browser", ref count, ref bytes);
                }
            }
        }
    }

    private static void CollectFirefox(CollectionContext context, string userDir, string username,
        ref int count, ref long bytes)
    {
        var ffProfilesDir = Path.Combine(userDir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
        if (!Directory.Exists(ffProfilesDir)) return;

        foreach (var profileDir in Directory.EnumerateDirectories(ffProfilesDir))
        {
            var profileName = Path.GetFileName(profileDir);

            foreach (var file in FirefoxProfileFiles)
            {
                var src = Path.Combine(profileDir, file);
                if (!File.Exists(src)) continue;
                var rel = Path.Combine("artifacts", "browser", "firefox", username, profileName, file);
                context.TryCaptureFile(src, rel, "browser", ref count, ref bytes);
            }

            // Extensions metadata
            var extDir = Path.Combine(profileDir, "extensions");
            if (Directory.Exists(extDir))
            {
                foreach (var ext in Directory.EnumerateFiles(extDir, "*.xpi"))
                {
                    var rel = Path.Combine("artifacts", "browser", "firefox", username, profileName, "extensions", Path.GetFileName(ext));
                    context.TryCaptureFile(ext, rel, "browser_extension", ref count, ref bytes);
                }
            }
        }

        var ffInstalls = Path.Combine(userDir, "AppData", "Roaming", "Mozilla", "Firefox", "installs.ini");
        if (File.Exists(ffInstalls))
        {
            var rel = Path.Combine("artifacts", "browser", "firefox", username, "installs.ini");
            context.TryCaptureFile(ffInstalls, rel, "browser", ref count, ref bytes);
        }
    }

    private static void CollectInternetExplorerLegacy(CollectionContext context, string userDir,
        string username, ref int count, ref long bytes)
    {
        // WebCacheV01.dat (IE/old Edge)
        var webCache = Path.Combine(userDir, "AppData", "Local", "Microsoft", "Windows", "WebCache", "WebCacheV01.dat");
        if (File.Exists(webCache))
        {
            var rel = Path.Combine("artifacts", "browser", "ie_edge_legacy", username, "WebCacheV01.dat");
            context.TryCaptureFile(webCache, rel, "browser", ref count, ref bytes);
        }
    }
}
