using System;

public static class ProgressLogger
{
    public enum ProgressLevel
    {
        START,
        IN_PROGRESS,
        COMPLETE,
        SUCCESS,
        FAILURE
    }

    public static void Log(ProgressLevel level, string message)
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        switch (level)
        {
            case ProgressLevel.START:
                Console.ForegroundColor = ConsoleColor.Blue;
                break;
            case ProgressLevel.IN_PROGRESS:
                Console.ForegroundColor = ConsoleColor.Cyan;
                break;
            case ProgressLevel.COMPLETE:
                Console.ForegroundColor = ConsoleColor.Green;
                break;
            case ProgressLevel.SUCCESS:
                Console.ForegroundColor = ConsoleColor.Magenta;
                break;
            case ProgressLevel.FAILURE:
                Console.ForegroundColor = ConsoleColor.Red;
                break;
        }
        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}");
        Console.ForegroundColor = originalColor;
    }

    public static void Start(string message) => Log(ProgressLevel.START, message);

    public static void InProgress(string message) => Log(ProgressLevel.IN_PROGRESS, message);

    public static void Complete(string message) => Log(ProgressLevel.COMPLETE, message);

    public static void Success(string message) => Log(ProgressLevel.SUCCESS, message);

    public static void Failure(string message) => Log(ProgressLevel.FAILURE, message);
}

public class Program
{
    public static void Main()
    {
        ProgressLogger.Start("Process started.");
        ProgressLogger.InProgress("Process ongoing...");
        ProgressLogger.Complete("Process completed.");
        ProgressLogger.Success("Process succeeded!");
        ProgressLogger.Failure("Process failed.");
    }
}
