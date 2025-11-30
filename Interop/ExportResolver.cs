using System.Runtime.InteropServices;
using Serilog;
using static ManualImageMapper.Interop.Structures;

namespace ManualImageMapper.Interop;

/// <summary>
/// Resolves function addresses from DLL export tables in remote processes.
/// Handles both direct exports and forwarded exports.
/// </summary>
public static class ExportResolver
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(ExportResolver));

    /// <summary>
    /// Resolves a function address by name from a remote module's export table.
    /// Handles forwarded exports by recursively resolving the target.
    ///
    /// FORWARDED EXPORT EXAMPLE:
    /// kernel32!InitializeSListHead -> NTDLL.RtlInitializeSListHead
    ///
    /// When the export RVA points within the export directory, it's a forwarder
    /// string rather than actual code. We parse this string and resolve from
    /// the target DLL.
    /// </summary>
    /// <param name="hProcess">Handle to the target process.</param>
    /// <param name="moduleBase">Base address of the module containing the export.</param>
    /// <param name="functionName">Name of the function to resolve.</param>
    /// <param name="pid">Process ID (needed for finding forwarded DLLs).</param>
    /// <param name="recursionDepth">Current depth (prevents infinite loops).</param>
    /// <returns>Address of the function in the remote process, or Zero if not found.</returns>
    public static nint GetRemoteProcAddress(
        nint hProcess,
        nint moduleBase,
        string functionName,
        int pid = 0,
        int recursionDepth = 0)
    {
        // Prevent infinite recursion on circular forwarders
        if (recursionDepth > Constants.MAX_FORWARDER_DEPTH)
        {
            Log.Warning("Export forwarder chain too deep for {Function}", functionName);
            return nint.Zero;
        }

        try
        {
            // Read DOS header
            var dosBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase, Marshal.SizeOf<IMAGE_DOS_HEADER>());
            var dos = MemoryHelpers.BytesToStructure<IMAGE_DOS_HEADER>(dosBytes);
            if (dos.e_magic != Constants.IMAGE_DOS_SIGNATURE) return nint.Zero;

            // Read NT headers
            var ntBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase + dos.e_lfanew, Marshal.SizeOf<IMAGE_NT_HEADERS64>());
            var nt = MemoryHelpers.BytesToStructure<IMAGE_NT_HEADERS64>(ntBytes);

            var exportDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.EXPORT];
            if (exportDir.Size == 0) return nint.Zero;

            // Read export directory
            var exportBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)exportDir.VirtualAddress, Marshal.SizeOf<IMAGE_EXPORT_DIRECTORY>());
            var exports = MemoryHelpers.BytesToStructure<IMAGE_EXPORT_DIRECTORY>(exportBytes);

            // Read the three export arrays
            var nameRvas = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)exports.AddressOfNames, (int)(exports.NumberOfNames * 4));
            var ordinals = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)exports.AddressOfNameOrdinals, (int)(exports.NumberOfNames * 2));
            var funcRvas = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)exports.AddressOfFunctions, (int)(exports.NumberOfFunctions * 4));

            // Search for the function by name
            for (uint i = 0; i < exports.NumberOfNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(nameRvas, (int)(i * 4));
                var nameBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)nameRva, 256);
                var name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0').Split('\0')[0];

                if (string.Equals(name, functionName, StringComparison.Ordinal))
                {
                    ushort ordinal = BitConverter.ToUInt16(ordinals, (int)(i * 2));
                    uint funcRva = BitConverter.ToUInt32(funcRvas, ordinal * 4);

                    // =========================================================
                    // CRITICAL: Check for forwarded exports!
                    // If the RVA points within the export directory, it's a
                    // forwarder string, NOT actual code.
                    // =========================================================
                    if (funcRva >= exportDir.VirtualAddress &&
                        funcRva < exportDir.VirtualAddress + exportDir.Size)
                    {
                        return ResolveForwardedExport(hProcess, moduleBase, funcRva, functionName, pid, recursionDepth);
                    }

                    // Direct export - return the function address
                    return moduleBase + (int)funcRva;
                }
            }
            return nint.Zero;
        }
        catch (Exception ex)
        {
            Log.Verbose(ex, "Failed to resolve export {Function}", functionName);
            return nint.Zero;
        }
    }

    /// <summary>
    /// Resolves a forwarded export by parsing the forwarder string and
    /// recursively resolving from the target DLL.
    ///
    /// Forwarder string format: "DllName.FunctionName"
    /// Example: "NTDLL.RtlInitializeSListHead"
    ///
    /// IMPORTANT: Handles API Set DLLs (api-ms-win-*) which are virtual DLLs
    /// that don't exist as real modules. We resolve them to their real DLLs.
    /// </summary>
    private static nint ResolveForwardedExport(
        nint hProcess,
        nint moduleBase,
        uint forwarderRva,
        string originalFunction,
        int pid,
        int recursionDepth)
    {
        // Read the forwarder string
        var forwarderBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)forwarderRva, 256);
        var forwarderStr = System.Text.Encoding.ASCII.GetString(forwarderBytes).Split('\0')[0];

        var dotIndex = forwarderStr.IndexOf('.');
        if (dotIndex <= 0)
        {
            Log.Warning("Invalid forwarder string for {Function}: {Forwarder}", originalFunction, forwarderStr);
            return nint.Zero;
        }

        var forwardDll = forwarderStr.Substring(0, dotIndex);
        var forwardFunc = forwarderStr.Substring(dotIndex + 1);

        // Add .dll extension if not present
        if (!forwardDll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            forwardDll += ".dll";

        Log.Verbose("Forwarded export: {Original} -> {Dll}!{Func}", originalFunction, forwardDll, forwardFunc);

        // Get the forwarded DLL's base in the remote process
        var forwardModuleBase = ModuleHelpers.GetRemoteModuleHandle(hProcess, pid, forwardDll);

        // If not found and it's an API Set, resolve to real DLL
        if (forwardModuleBase == nint.Zero && IsApiSetDll(forwardDll))
        {
            forwardModuleBase = ResolveApiSetToRealModule(hProcess, pid, forwardDll);
        }

        if (forwardModuleBase == nint.Zero)
        {
            Log.Warning("Forwarded DLL not found: {Dll}", forwardDll);
            return nint.Zero;
        }

        // Recursively resolve from the forwarded DLL
        return GetRemoteProcAddress(hProcess, forwardModuleBase, forwardFunc, pid, recursionDepth + 1);
    }

    /// <summary>
    /// Checks if a DLL name is an API Set (virtual DLL).
    /// API Sets have names like "api-ms-win-*" or "ext-ms-*".
    /// </summary>
    private static bool IsApiSetDll(string dllName)
    {
        return dllName.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) ||
               dllName.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolves an API Set DLL to its real implementation DLL.
    ///
    /// API Sets are virtual DLLs that Windows maps to real DLLs at load time.
    /// Common mappings:
    /// - api-ms-win-core-* → kernelbase.dll (most common)
    /// - api-ms-win-crt-* → ucrtbase.dll
    /// - api-ms-win-core-com-* → combase.dll
    /// - ext-ms-* → various
    /// </summary>
    private static nint ResolveApiSetToRealModule(nint hProcess, int pid, string apiSetName)
    {
        // Common API Set mappings based on the API Set name patterns
        // These are the most common fallback DLLs for API Sets
        string[] fallbackDlls;

        if (apiSetName.StartsWith("api-ms-win-crt-", StringComparison.OrdinalIgnoreCase))
        {
            fallbackDlls = ["ucrtbase.dll"];
        }
        else if (apiSetName.StartsWith("api-ms-win-core-com-", StringComparison.OrdinalIgnoreCase))
        {
            fallbackDlls = ["combase.dll"];
        }
        else if (apiSetName.StartsWith("api-ms-win-core-", StringComparison.OrdinalIgnoreCase) ||
                 apiSetName.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase))
        {
            // Most api-ms-win-core-* and api-ms-win-* map to kernelbase.dll
            // Some may also be in ntdll.dll
            fallbackDlls = ["kernelbase.dll", "ntdll.dll", "kernel32.dll"];
        }
        else if (apiSetName.StartsWith("ext-ms-win-", StringComparison.OrdinalIgnoreCase))
        {
            // Extension API sets vary widely
            fallbackDlls = ["kernelbase.dll", "kernel32.dll"];
        }
        else
        {
            // Generic fallback
            fallbackDlls = ["kernelbase.dll", "ntdll.dll"];
        }

        foreach (var dll in fallbackDlls)
        {
            var moduleBase = ModuleHelpers.GetRemoteModuleHandle(hProcess, pid, dll);
            if (moduleBase != nint.Zero)
            {
                Log.Verbose("Resolved API Set {ApiSet} -> {RealDll}", apiSetName, dll);
                return moduleBase;
            }
        }

        Log.Warning("Could not resolve API Set {ApiSet} to any known DLL", apiSetName);
        return nint.Zero;
    }

    /// <summary>
    /// Resolves a function address by ordinal from a remote module's export table.
    /// Note: Ordinal exports can also be forwarded, but this is rare.
    /// </summary>
    /// <param name="hProcess">Handle to the target process.</param>
    /// <param name="moduleBase">Base address of the module.</param>
    /// <param name="ordinal">The export ordinal.</param>
    /// <returns>Address of the function, or Zero if not found.</returns>
    public static nint GetRemoteProcAddressByOrdinal(nint hProcess, nint moduleBase, ushort ordinal)
    {
        try
        {
            // Read DOS header
            var dosBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase, Marshal.SizeOf<IMAGE_DOS_HEADER>());
            var dos = MemoryHelpers.BytesToStructure<IMAGE_DOS_HEADER>(dosBytes);
            if (dos.e_magic != Constants.IMAGE_DOS_SIGNATURE) return nint.Zero;

            // Read NT headers
            var ntBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase + dos.e_lfanew, Marshal.SizeOf<IMAGE_NT_HEADERS64>());
            var nt = MemoryHelpers.BytesToStructure<IMAGE_NT_HEADERS64>(ntBytes);

            var exportDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.EXPORT];
            if (exportDir.Size == 0) return nint.Zero;

            // Read export directory
            var exportBytes = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)exportDir.VirtualAddress, Marshal.SizeOf<IMAGE_EXPORT_DIRECTORY>());
            var exports = MemoryHelpers.BytesToStructure<IMAGE_EXPORT_DIRECTORY>(exportBytes);

            // Calculate the actual index (ordinal - Base)
            uint funcIndex = ordinal - exports.Base;
            if (funcIndex >= exports.NumberOfFunctions) return nint.Zero;

            // Read the function RVA
            var funcRvas = MemoryHelpers.ReadMemory(hProcess, moduleBase + (int)exports.AddressOfFunctions, (int)(exports.NumberOfFunctions * 4));
            uint funcRva = BitConverter.ToUInt32(funcRvas, (int)(funcIndex * 4));

            // Note: Ordinal exports can also be forwarded, but we don't handle that here
            // as it's extremely rare in practice

            return moduleBase + (int)funcRva;
        }
        catch
        {
            return nint.Zero;
        }
    }
}
