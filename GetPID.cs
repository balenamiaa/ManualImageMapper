using System.Diagnostics;

namespace ManualImageMapper;



public static class GetPiD
{


    /// <summary>
    /// Does fuzzy matching on the process name to find the process identifier. Chooses the process with the most similar name.
    /// </summary>
    /// <param name="processName">The name of the process to find.</param>
    /// <returns>The process identifier if found, otherwise null.</returns>
    public static int? FromProcessName(string processName)
    {
        var processes = Process.GetProcesses();

        var bestMatch = processes.OrderBy(p => LevenshteinDistance.Calculate(p.ProcessName, processName)).FirstOrDefault();

        Console.WriteLine(bestMatch?.ProcessName);

        return bestMatch?.Id;
    }
}