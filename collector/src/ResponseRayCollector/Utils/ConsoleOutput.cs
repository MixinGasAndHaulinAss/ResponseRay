namespace ResponseRayCollector.Utils;

public static class ConsoleOutput
{
    private static readonly object Lock = new();

    public static void Banner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
  ____                                      ____
 |  _ \ ___  ___ _ __   ___  _ __  ___  ___|  _ \ __ _ _   _
 | |_) / _ \/ __| '_ \ / _ \| '_ \/ __|/ _ \ |_) / _` | | | |
 |  _ <  __/\__ \ |_) | (_) | | | \__ \  __/  _ < (_| | |_| |
 |_| \_\___||___/ .__/ \___/|_| |_|___/\___|_| \_\__,_|\__, |
                |_|   Windows Artifact Collector        |___/
");
        Console.ResetColor();
        Console.WriteLine($"  Version {typeof(ConsoleOutput).Assembly.GetName().Version}");
        Console.WriteLine($"  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine();
    }

    public static void Info(string message)
    {
        lock (Lock)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }
    }

    public static void Warning(string message)
    {
        lock (Lock)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[!] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }
    }

    public static void Error(string message)
    {
        lock (Lock)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[-] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }
    }

    public static void Status(string message)
    {
        lock (Lock)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    ");
            Console.ResetColor();
            Console.WriteLine(message);
        }
    }

    public static void Section(string title)
    {
        lock (Lock)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"=== {title} ===");
            Console.ResetColor();
        }
    }
}
