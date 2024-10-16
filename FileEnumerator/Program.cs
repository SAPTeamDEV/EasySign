using System;
using System.Collections.Generic;
using System.IO;

public class Program
{
    public static IEnumerable<string> SafeEnumerateFiles(string path, string searchPattern)
    {
        Queue<string> folders = new Queue<string>();
        folders.Enqueue(path);

        while (folders.Count > 0)
        {
            string currentDir = folders.Dequeue();
            string[] subDirs;
            string[] files = null;

            try
            {
                files = Directory.GetFiles(currentDir, searchPattern);
            }
            catch (UnauthorizedAccessException) { }
            catch (DirectoryNotFoundException) { }

            if (files != null)
            {
                foreach (string file in files)
                {
                    yield return file;
                }
            }

            try
            {
                subDirs = Directory.GetDirectories(currentDir);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }

            foreach (string str in subDirs)
            {
                folders.Enqueue(str);
            }
        }
    }

    public static void Main(string[] args)
    {
        string path = args[0];
        foreach (string file in SafeEnumerateFiles(path, "*"))
        {
            try
            {
                // Process your file here
                Console.WriteLine($"Processing {file}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to process {file}: {ex.Message}");
            }
        }
    }
}
