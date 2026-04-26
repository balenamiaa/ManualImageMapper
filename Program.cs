using System.Diagnostics;
using Serilog;
using ManualImageMapper;

using static ManualImageMapper.Interop.Win32;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.Console()
    .CreateLogger();

var logger = Log.ForContext("SourceContext", "Main");

var cmdArgs = Environment.GetCommandLineArgs();

if (cmdArgs.Length < 3 || cmdArgs.Length > 4)
{
    logger.Information("Usage: {Usage} <dll path> <process name or pid> [method]", Path.GetFileName(cmdArgs[0]));
    logger.Information("  method: 'hijack' (default, stealth), 'hijack-debug' (verbose stub diagnostics), or 'thread' for CreateRemoteThread");
    return;
}

string dllPath = cmdArgs[1];
string target = cmdArgs[2];
string method = cmdArgs.Length > 3 ? cmdArgs[3].ToLowerInvariant() : "hijack";

InjectionMode injectionMode = method switch
{
    "hijack" or "h" => new InjectionMode.ThreadHijacking(),
    "hijack-debug" or "hd" => new InjectionMode.ThreadHijacking(LogStubBytes: true),
    "thread" or "t" => new InjectionMode.CreateRemoteThread(),
    _ => throw new ArgumentException($"Invalid method '{method}'. Use 'hijack', 'hijack-debug', or 'thread'.")
};

if (!File.Exists(dllPath))
{
    logger.Error("DLL not found: {DllPath}", dllPath);
    return;
}

int? pid = null;

// If numeric, treat as PID directly
if (int.TryParse(target, out var parsedPid))
{
    try
    {
        // Throws if PID not running
        _ = Process.GetProcessById(parsedPid);
        pid = parsedPid;
    }
    catch (ArgumentException)
    {
        // fall-through – handled below
    }
}

pid ??= GetProcessIdFromProcessName(target);

if (pid is not int validPid)
{
    logger.Error("Could not resolve process {Target}", target);
    return;
}


byte[] dllBytes;
try
{
    dllBytes = File.ReadAllBytes(dllPath);
}
catch (Exception ex)
{
    logger.Error(ex, "Failed to read DLL");
    return;
}

try
{
    string methodName = injectionMode switch
    {
        InjectionMode.ThreadHijacking => "thread hijacking",
        InjectionMode.CreateRemoteThread => "CreateRemoteThread",
        _ => injectionMode.GetType().Name
    };

    var dllFileName = Path.GetFileName(dllPath);
    logger.Information("Injecting {Dll} into PID {Pid} using {Method}",
        dllFileName, validPid, methodName);
    ManualMapper.Inject(dllBytes, validPid, injectionMode, dllFileName);
    logger.Information("Injection completed successfully");
}
catch (Exception ex)
{
    logger.Error(ex, "Injection failed");
}