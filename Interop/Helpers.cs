// =============================================================================
// Helpers.cs - Memory, Process, and Module Helper Functions
// =============================================================================
//
// This module provides convenient wrapper functions for common operations:
// - Memory allocation, reading, writing in remote processes
// - Module enumeration and lookup
// - PE parsing utilities
// - Process information queries
//
// These are the "building blocks" used by higher-level mapping operations.
// =============================================================================

using System.Diagnostics;
using System.Runtime.InteropServices;
using Serilog;
using ManualImageMapper.StringMatching;
using static ManualImageMapper.Interop.Structures;

namespace ManualImageMapper.Interop;

/// <summary>
/// Helper functions for memory operations in remote processes.
/// </summary>
public static class MemoryHelpers
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(MemoryHelpers));

    /// <summary>
    /// Opens a process with full access rights.
    /// </summary>
    /// <exception cref="System.ComponentModel.Win32Exception">If OpenProcess fails.</exception>
    public static nint OpenTargetProcess(int pid)
    {
        var handle = NativeMethods.OpenProcess(Constants.PROCESS_ALL_ACCESS, false, pid);
        if (handle == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess failed for PID {pid}");
        Log.Debug("Opened process {Pid} -> 0x{Handle:X}", pid, (ulong)handle);
        return handle;
    }

    /// <summary>
    /// Safely closes a handle (no-op if Zero).
    /// </summary>
    public static void CloseHandleSafe(nint handle)
    {
        if (handle != nint.Zero) NativeMethods.CloseHandle(handle);
    }

    /// <summary>
    /// Allocates memory in a remote process.
    /// </summary>
    /// <exception cref="System.ComponentModel.Win32Exception">If allocation fails.</exception>
    public static nint AllocateMemory(nint hProcess, uint size, uint protection = Constants.PAGE_READWRITE)
    {
        var addr = NativeMethods.VirtualAllocEx(hProcess, nint.Zero, size, Constants.MEM_COMMIT | Constants.MEM_RESERVE, protection);
        if (addr == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");
        Log.Debug("Allocated {Size} bytes at 0x{Addr:X} (prot 0x{Prot:X})", size, (ulong)addr, protection);
        return addr;
    }

    /// <summary>
    /// Frees memory in a remote process.
    /// </summary>
    public static void FreeMemory(nint hProcess, nint address)
    {
        if (address == nint.Zero) return;
        if (!NativeMethods.VirtualFreeEx(hProcess, address, 0, Constants.MEM_RELEASE))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualFreeEx failed");
    }

    /// <summary>
    /// Writes data to a remote process.
    /// </summary>
    /// <exception cref="System.ComponentModel.Win32Exception">If write fails.</exception>
    public static void WriteMemory(nint hProcess, nint baseAddress, byte[] data)
    {
        if (!NativeMethods.WriteProcessMemory(hProcess, baseAddress, data, (uint)data.Length, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
    }

    /// <summary>
    /// Reads data from a remote process.
    /// </summary>
    /// <exception cref="System.ComponentModel.Win32Exception">If read fails.</exception>
    public static byte[] ReadMemory(nint hProcess, nint baseAddress, int size)
    {
        var buffer = new byte[size];
        if (!NativeMethods.ReadProcessMemory(hProcess, baseAddress, buffer, size, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");
        return buffer;
    }

    /// <summary>
    /// Changes memory protection in a remote process.
    /// </summary>
    /// <returns>Previous protection value.</returns>
    public static uint ProtectMemory(nint hProcess, nint address, uint size, uint newProtect)
    {
        if (!NativeMethods.VirtualProtectEx(hProcess, address, size, newProtect, out var oldProtect))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtectEx failed");
        return oldProtect;
    }

    /// <summary>
    /// Creates a remote thread and optionally waits for completion.
    /// </summary>
    public static nint CreateRemoteThreadAndWait(nint hProcess, nint startAddress, nint parameter, bool wait = true)
    {
        var hThread = NativeMethods.CreateRemoteThread(hProcess, nint.Zero, 0, startAddress, parameter, 0, nint.Zero);
        if (hThread == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");

        if (wait)
        {
            NativeMethods.WaitForSingleObject(hThread, Constants.INFINITE);
            CloseHandleSafe(hThread);
            return nint.Zero;
        }
        return hThread;
    }

    /// <summary>
    /// Converts a byte array to a structure.
    /// </summary>
    public static T BytesToStructure<T>(byte[] buffer, int offset = 0) where T : struct
    {
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var ptr = IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            return Marshal.PtrToStructure<T>(ptr)!;
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Converts a structure to a byte array.
    /// </summary>
    public static byte[] StructureToBytes<T>(T structure) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        var bytes = new byte[size];
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(structure, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
        return bytes;
    }
}

/// <summary>
/// Helper functions for module enumeration and lookup.
/// </summary>
public static class ModuleHelpers
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(ModuleHelpers));

    /// <summary>
    /// Gets a module's base address in a REMOTE process.
    /// This is the correct way to resolve imports - NOT using local GetModuleHandle!
    /// </summary>
    public static nint GetRemoteModuleHandle(nint hProcess, int pid, string moduleName)
    {
        var snap = NativeMethods.CreateToolhelp32Snapshot(
            Constants.TH32CS_SNAPMODULE | Constants.TH32CS_SNAPMODULE32, (uint)pid);
        if (snap == nint.Zero || snap == new nint(-1))
            return nint.Zero;

        try
        {
            var entry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };
            if (!NativeMethods.Module32First(snap, ref entry)) return nint.Zero;

            do
            {
                if (string.Equals(entry.szModule, moduleName, StringComparison.OrdinalIgnoreCase))
                    return entry.modBaseAddr;
            } while (NativeMethods.Module32Next(snap, ref entry));

            return nint.Zero;
        }
        finally
        {
            MemoryHelpers.CloseHandleSafe(snap);
        }
    }

    /// <summary>
    /// Finds a process ID by name using fuzzy matching.
    /// </summary>
    public static int? GetProcessIdFromProcessName(string processName)
    {
        var processes = Process.GetProcesses();
        var bestMatch = processes
            .Where(p => p.ProcessName.Contains(processName, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => LevenshteinDistance.Calculate(p.ProcessName, processName))
            .FirstOrDefault();
        return bestMatch?.Id;
    }

    /// <summary>
    /// Checks if a process is 64-bit.
    /// </summary>
    public static bool IsProcess64Bit(nint hProcess)
    {
        if (!Environment.Is64BitOperatingSystem) return false;
        try
        {
            if (NativeMethods.IsWow64Process2(hProcess, out ushort procMachine, out _))
                return procMachine == 0;
        }
        catch (EntryPointNotFoundException) { }
        return NativeMethods.IsWow64Process(hProcess, out bool isWow) ? !isWow : true;
    }
}

/// <summary>
/// Helper functions for PE parsing.
/// </summary>
public static class PeHelpers
{
    /// <summary>
    /// Parses the DOS header from a PE image.
    /// </summary>
    public static IMAGE_DOS_HEADER GetDosHeader(byte[] image)
    {
        int dosHeaderSize = Marshal.SizeOf<IMAGE_DOS_HEADER>();
        if (image == null || image.Length < dosHeaderSize)
            throw new InvalidOperationException($"Image too small for DOS header");

        var dos = MemoryHelpers.BytesToStructure<IMAGE_DOS_HEADER>(image, 0);
        if (dos.e_magic != Constants.IMAGE_DOS_SIGNATURE)
            throw new InvalidOperationException($"Invalid DOS signature: 0x{dos.e_magic:X4}");

        return dos;
    }

    /// <summary>
    /// Parses the NT headers from a PE image.
    /// </summary>
    public static IMAGE_NT_HEADERS64 GetNtHeaders(byte[] image)
    {
        var dos = GetDosHeader(image);
        if (dos.e_lfanew < 0 || dos.e_lfanew + Marshal.SizeOf<IMAGE_NT_HEADERS64>() > image.Length)
            throw new InvalidOperationException($"Invalid e_lfanew: 0x{dos.e_lfanew:X}");

        var nt = MemoryHelpers.BytesToStructure<IMAGE_NT_HEADERS64>(image, dos.e_lfanew);
        if (nt.Signature != Constants.IMAGE_NT_SIGNATURE)
            throw new InvalidOperationException($"Invalid PE signature: 0x{nt.Signature:X8}");
        if (nt.FileHeader.Machine != MachineType.IMAGE_FILE_MACHINE_AMD64)
            throw new InvalidOperationException($"Unsupported machine: {nt.FileHeader.Machine}");
        if (nt.OptionalHeader.Magic != MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            throw new InvalidOperationException($"Invalid magic: 0x{(ushort)nt.OptionalHeader.Magic:X}");

        return nt;
    }

    /// <summary>
    /// Parses the section headers from a PE image.
    /// </summary>
    public static List<IMAGE_SECTION_HEADER> GetSectionHeaders(byte[] image)
    {
        var dos = GetDosHeader(image);
        var nt = GetNtHeaders(image);
        int sectionOffset = dos.e_lfanew + Marshal.SizeOf<IMAGE_NT_HEADERS64>();
        int sectionSize = Marshal.SizeOf<IMAGE_SECTION_HEADER>();
        var list = new List<IMAGE_SECTION_HEADER>();
        for (int i = 0; i < nt.FileHeader.NumberOfSections; i++)
            list.Add(MemoryHelpers.BytesToStructure<IMAGE_SECTION_HEADER>(image, sectionOffset + i * sectionSize));
        return list;
    }

    /// <summary>
    /// Aligns a value up to the specified alignment.
    /// </summary>
    public static uint AlignUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);

    /// <summary>
    /// Converts section characteristics to page protection flags.
    /// </summary>
    public static uint CharacteristicsToProtection(uint characteristics)
    {
        var exec = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
        var read = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
        var write = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;

        return (exec, read, write) switch
        {
            (false, false, false) => Constants.PAGE_NOACCESS,
            (false, true, false) => Constants.PAGE_READONLY,
            (false, true, true) => Constants.PAGE_READWRITE,
            (true, true, false) => Constants.PAGE_EXECUTE_READ,
            (true, true, true) => Constants.PAGE_EXECUTE_READWRITE,
            (true, false, false) => Constants.PAGE_EXECUTE,
            _ => Constants.PAGE_NOACCESS
        };
    }
}

/// <summary>
/// Helper functions for privilege management.
/// </summary>
public static class PrivilegeHelpers
{
    /// <summary>
    /// Enables SeDebugPrivilege for the current process.
    /// Required for accessing some protected processes.
    /// </summary>
    public static bool EnableSeDebugPrivilege()
    {
        try
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                Constants.TOKEN_ADJUST_PRIVILEGES | Constants.TOKEN_QUERY, out var tokenHandle))
                return false;

            try
            {
                if (!NativeMethods.LookupPrivilegeValue(null, Constants.SE_DEBUG_NAME, out var luid))
                    return false;

                var privileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privilege = new LUID_AND_ATTRIBUTES
                    {
                        Luid = new LUID { LowPart = (uint)luid, HighPart = (int)(luid >> 32) },
                        Attributes = Constants.SE_PRIVILEGE_ENABLED
                    }
                };

                return NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref privileges, 0, nint.Zero, nint.Zero);
            }
            finally
            {
                MemoryHelpers.CloseHandleSafe(tokenHandle);
            }
        }
        catch { return false; }
    }
}

/// <summary>
/// Helper functions for thread context manipulation.
/// </summary>
public static class ThreadHelpers
{
    /// <summary>
    /// Gets the thread context (CPU state) for a thread.
    /// The context must be 16-byte aligned.
    /// </summary>
    public static unsafe bool TryGetThreadContext(nint hThread, out CONTEXT64 context)
    {
        context = default;
        int size = Marshal.SizeOf<CONTEXT64>();
        nint raw = Marshal.AllocHGlobal(size + 16);
        try
        {
            nint aligned = (nint)(((long)raw + 15) & ~0xF);
            new Span<byte>((void*)aligned, size).Clear();
            Marshal.WriteInt32(aligned, 0x30, (int)Constants.CONTEXT_ALL);
            if (!NativeMethods.GetThreadContextRaw(hThread, aligned)) return false;
            context = Marshal.PtrToStructure<CONTEXT64>(aligned)!;
            return true;
        }
        finally { Marshal.FreeHGlobal(raw); }
    }

    /// <summary>
    /// Sets the thread context (CPU state) for a thread.
    /// </summary>
    public static unsafe bool TrySetThreadContext(nint hThread, in CONTEXT64 context)
    {
        int size = Marshal.SizeOf<CONTEXT64>();
        nint raw = Marshal.AllocHGlobal(size + 16);
        try
        {
            nint aligned = (nint)(((long)raw + 15) & ~0xF);
            Marshal.StructureToPtr(context, aligned, false);
            return NativeMethods.SetThreadContextRaw(hThread, aligned);
        }
        finally { Marshal.FreeHGlobal(raw); }
    }
}
