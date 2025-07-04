using System.Runtime.InteropServices;
using System.Diagnostics;
using Serilog;
using ManualImageMapper.StringMatching;

using static ManualImageMapper.WinApi.Enums;
using static ManualImageMapper.WinApi.Structs;
using static ManualImageMapper.WinApi.Constants;

namespace ManualImageMapper.WinApi;

/// <summary>
/// Foreign Function Interface providing Win32 API wrappers and PE manipulation utilities.
/// </summary>
public static partial class Methods
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(Methods));

    #region Low Level Native Methods
    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial nint GetProcAddress(nint hModule, string procName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint GetProcAddress(nint hModule, nint procName);

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleHandleA", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial nint GetModuleHandle(string lpModuleName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint VirtualAllocEx(nint hProcess, nint lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool VirtualFreeEx(nint hProcess, nint lpAddress, int dwSize, uint dwFreeType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, uint nSize, out nint lpNumberOfBytesWritten);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool ReadProcessMemory(nint hProcess, nint lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesRead);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, uint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, nint lpThreadId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool VirtualProtectEx(nint hProcess, nint lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [LibraryImport("ntdll.dll")]
    public static partial int NtQueryInformationProcess(nint ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, out PROCESS_BASIC_INFORMATION ProcessInformation, int ProcessInformationLength, out int ReturnLength);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess, out nint TokenHandle);

    [LibraryImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueA", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool AdjustTokenPrivileges(nint TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, nint PreviousState, nint ReturnLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "IsWow64Process2")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsWow64Process2(nint hProcess, out ushort processMachine, out ushort nativeMachine);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsWow64Process(nint hProcess, [MarshalAs(UnmanagedType.Bool)] out bool isWow64);

    [LibraryImport("user32.dll", SetLastError = true, EntryPoint = "PostThreadMessageW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PostThreadMessage(uint idThread, uint msg, nuint wParam, nint lParam);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint QueueUserAPC(nint pfnAPC, nint hThread, nuint dwData);

    [LibraryImport("ntdll.dll")]
    public static partial uint NtAlertThread(nint hThread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint SuspendThread(nint hThread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint ResumeThread(nint hThread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool GetThreadContext(nint hThread, ref CONTEXT64 lpContext);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool SetThreadContext(nint hThread, ref CONTEXT64 lpContext);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool FlushInstructionCache(nint hProcess, nint lpBaseAddress, nuint dwSize);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Thread32First(nint hSnapshot, ref THREADENTRY32 lpte);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Thread32Next(nint hSnapshot, ref THREADENTRY32 lpte);

    [LibraryImport("kernel32.dll", EntryPoint = "GetThreadContext", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetThreadContextRaw(nint hThread, nint lpContext);

    [LibraryImport("kernel32.dll", EntryPoint = "SetThreadContext", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetThreadContextRaw(nint hThread, nint lpContext);
    #endregion

    #region Higher Level Methods
    /// <summary>
    /// Opens the target process with PROCESS_ALL_ACCESS. Throws on failure.
    /// </summary>
    public static nint OpenTargetProcess(int pid)
    {
        var handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (handle == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess failed for PID {pid}");
        Log.Debug("Opened process {Pid} -> 0x{Handle:X}", pid, (ulong)handle);
        return handle;
    }

    /// <summary>
    /// Safely closes a handle, ignoring zero handles.
    /// </summary>
    public static void CloseHandleSafe(nint handle)
    {
        if (handle != nint.Zero)
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// Allocates memory in the remote process with MEM_COMMIT | MEM_RESERVE.
    /// </summary>
    public static nint AllocateMemory(nint hProcess, uint size, uint protection = PAGE_READWRITE)
    {
        var addr = VirtualAllocEx(hProcess, nint.Zero, size, MEM_COMMIT | MEM_RESERVE, protection);
        if (addr == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");
        Log.Debug("Allocated {Size} bytes in target at 0x{Addr:X} (prot 0x{Prot:X})", size, (ulong)addr, protection);
        return addr;
    }

    /// <summary>
    /// Frees previously allocated remote memory.
    /// </summary>
    public static void FreeMemory(nint hProcess, nint address)
    {
        if (address == nint.Zero) return;
        Log.Debug("Freeing remote memory at 0x{Addr:X}", (ulong)address);
        if (!VirtualFreeEx(hProcess, address, 0, MEM_RELEASE))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualFreeEx failed");
    }

    /// <summary>
    /// Writes a byte array to the specified remote address.
    /// </summary>
    public static void WriteMemory(nint hProcess, nint baseAddress, byte[] data)
    {
        if (!WriteProcessMemory(hProcess, baseAddress, data, (uint)data.Length, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
    }

    /// <summary>
    /// Reads bytes from the remote address.
    /// </summary>
    public static byte[] ReadMemory(nint hProcess, nint baseAddress, int size)
    {
        var buffer = new byte[size];
        if (!ReadProcessMemory(hProcess, baseAddress, buffer, size, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");
        return buffer;
    }

    /// <summary>
    /// Changes the protection of a remote memory region and returns the old protection.
    /// </summary>
    public static uint ProtectMemory(nint hProcess, nint address, uint size, uint newProtect)
    {
        if (!VirtualProtectEx(hProcess, address, size, newProtect, out var oldProtect))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtectEx failed");
        Log.Debug("Protect 0x{Addr:X} size {Size} -> 0x{NewProt:X} (old 0x{Old:X})", (ulong)address, size, newProtect, oldProtect);
        return oldProtect;
    }

    /// <summary>
    /// Creates a remote thread and optionally waits for it to finish.
    /// </summary>
    public static nint CreateRemoteThreadAndWait(nint hProcess, nint startAddress, nint parameter, bool wait = true)
    {
        var hThread = CreateRemoteThread(hProcess, nint.Zero, 0, startAddress, parameter, 0, nint.Zero);
        if (hThread == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");

        Log.Debug("Created remote thread 0x{Thread:X} start 0x{Start:X} param 0x{Param:X}", (ulong)hThread, (ulong)startAddress, (ulong)parameter);

        if (wait)
        {
            WaitForSingleObject(hThread, INFINITE);
            Log.Verbose("Waited for thread 0x{Thread:X} to finish", (ulong)hThread);
            CloseHandleSafe(hThread);
            return nint.Zero;
        }
        return hThread;
    }

    /// <summary>
    /// Converts a raw byte buffer to a structure.
    /// </summary>
    public static T BytesToStructure<T>(byte[] buffer, int offset = 0) where T : struct
    {
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var ptr = System.IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            return Marshal.PtrToStructure<T>(ptr)!;
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Reads the DOS header from the PE image.
    /// </summary>
    public static IMAGE_DOS_HEADER GetDosHeader(byte[] image) => BytesToStructure<IMAGE_DOS_HEADER>(image, 0);

    /// <summary>
    /// Reads the NT headers from the PE image.
    /// </summary>
    public static IMAGE_NT_HEADERS64 GetNtHeaders(byte[] image)
    {
        var dos = GetDosHeader(image);
        return BytesToStructure<IMAGE_NT_HEADERS64>(image, dos.e_lfanew);
    }

    /// <summary>
    /// Returns all section headers for the PE image.
    /// </summary>
    public static List<IMAGE_SECTION_HEADER> GetSectionHeaders(byte[] image)
    {
        var dos = GetDosHeader(image);
        var nt = GetNtHeaders(image);
        int sectionOffset = dos.e_lfanew + Marshal.SizeOf<IMAGE_NT_HEADERS64>();
        int sectionSize = Marshal.SizeOf<IMAGE_SECTION_HEADER>();
        var list = new List<IMAGE_SECTION_HEADER>();
        for (int i = 0; i < nt.FileHeader.NumberOfSections; i++)
        {
            list.Add(BytesToStructure<IMAGE_SECTION_HEADER>(image, sectionOffset + i * sectionSize));
        }
        return list;
    }

    /// <summary>
    /// Aligns value up to the next multiple of alignment.
    /// </summary>
    public static uint AlignUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);

    /// <summary>
    /// Maps PE section characteristics to Windows memory protection flags.
    /// </summary>
    public static uint CharacteristicsToProtection(uint characteristics)
    {
        var exec = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
        var read = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
        var write = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;

        return (exec, read, write) switch
        {
            (false, false, false) => PAGE_NOACCESS,
            (false, true, false) => PAGE_READONLY,
            (false, true, true) => PAGE_READWRITE,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, true, true) => PAGE_EXECUTE_READWRITE,
            (true, false, false) => PAGE_EXECUTE,
            _ => PAGE_NOACCESS
        };
    }

    /// <summary>
    /// Maps PE sections into remote memory. Sections remain RW unless applyFinalProtection is true.
    /// </summary>
    public static void MapSections(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, IReadOnlyList<IMAGE_SECTION_HEADER> sections, bool applyFinalProtection = false)
    {
        Log.Debug("MapSections copying {Count} sections", sections.Count);

        int idx = 0;
        foreach (var section in sections)
        {
            var rawOffset = (int)section.PointerToRawData;
            var rawSize = (int)section.SizeOfRawData;
            var slice = localImage.Slice(rawOffset, rawSize);

            var remoteAddress = remoteBase + (int)section.VirtualAddress;
            WriteMemory(hProcess, remoteAddress, slice.ToArray());
            Log.Verbose("Section #{Idx} VA 0x{VA:X} rawSize {Size}", idx++, section.VirtualAddress, rawSize);
        }

        if (applyFinalProtection)
        {
            SetSectionProtections(hProcess, remoteBase, sections);
        }
    }

    /// <summary>
    /// Applies final protection flags to sections. Call after relocations and IAT patching.
    /// </summary>
    public static void SetSectionProtections(nint hProcess, nint remoteBase, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        foreach (var section in sections)
        {
            var size = AlignUp(section.VirtualSize, 0x1000);
            var prot = CharacteristicsToProtection(section.Characteristics);
            var remoteAddress = remoteBase + (int)section.VirtualAddress;
            ProtectMemory(hProcess, remoteAddress, size, prot);
        }
    }

    /// <summary>
    /// Attempts to enable SeDebugPrivilege for the current process.
    /// </summary>
    public static bool EnableSeDebugPrivilege()
    {
        try
        {
            var currentProcess = GetCurrentProcess();
            if (!OpenProcessToken(currentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var tokenHandle))
            {
                Log.Warning("Failed to open process token for privilege adjustment (err {Err})", Marshal.GetLastWin32Error());
                return false;
            }

            try
            {
                if (!LookupPrivilegeValue(null!, SE_DEBUG_NAME, out var luid))
                {
                    Log.Warning("Failed to lookup SeDebugPrivilege (err {Err})", Marshal.GetLastWin32Error());
                    return false;
                }

                var privileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privilege = new LUID_AND_ATTRIBUTES
                    {
                        Luid = new LUID { LowPart = (uint)luid, HighPart = (int)(luid >> 32) },
                        Attributes = SE_PRIVILEGE_ENABLED
                    }
                };

                if (!AdjustTokenPrivileges(tokenHandle, false, ref privileges, 0, nint.Zero, nint.Zero))
                {
                    Log.Warning("Failed to adjust token privileges (err {Err})", Marshal.GetLastWin32Error());
                    return false;
                }

                Log.Debug("Successfully enabled SeDebugPrivilege");
                return true;
            }
            finally
            {
                CloseHandleSafe(tokenHandle);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Exception while enabling SeDebugPrivilege");
            return false;
        }
    }

    /// <summary>
    /// Determines if the specified process is 64-bit.
    /// </summary>
    public static bool IsProcess64Bit(nint hProcess)
    {
        if (!Environment.Is64BitOperatingSystem)
            return false;

        try
        {
            if (IsWow64Process2(hProcess, out ushort procMachine, out _))
            {
                return procMachine == 0;
            }
        }
        catch (EntryPointNotFoundException)
        {
        }

        if (IsWow64Process(hProcess, out bool isWow))
            return !isWow;

        return true;
    }

    /// <summary>
    /// Reads CONTEXT64 structure using 16-byte-aligned buffer to satisfy GetThreadContext requirements.
    /// </summary>
    public static unsafe bool TryGetThreadContext(nint hThread, out CONTEXT64 context)
    {
        context = default;
        int size = Marshal.SizeOf<CONTEXT64>();
        nint raw = Marshal.AllocHGlobal(size + 16);
        try
        {
            nint aligned = (nint)(((long)raw + 15) & ~0xF);
            Span<byte> clear = new Span<byte>((void*)aligned, size);
            clear.Clear();
            Marshal.WriteInt32(aligned, 0x30, (int)CONTEXT_ALL);

            if (!GetThreadContextRaw(hThread, aligned)) return false;
            context = Marshal.PtrToStructure<CONTEXT64>(aligned)!;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }
    }

    /// <summary>
    /// Writes CONTEXT64 structure using 16-byte-aligned buffer to satisfy SetThreadContext requirements.
    /// </summary>
    public static unsafe bool TrySetThreadContext(nint hThread, in CONTEXT64 context)
    {
        int size = Marshal.SizeOf<CONTEXT64>();
        nint raw = Marshal.AllocHGlobal(size + 16);
        try
        {
            nint aligned = (nint)(((long)raw + 15) & ~0xF);
            Marshal.StructureToPtr(context, aligned, false);
            return SetThreadContextRaw(hThread, aligned);
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }
    }

    /// <summary>
    /// Does fuzzy matching on the process names that contain processName to find the process identifier. Chooses the process with the most similar name.
    /// </summary>
    /// <param name="processName">The name of the process to find.</param>
    /// <returns>The process identifier if found, otherwise null.</returns>
    public static int? GetProcessIdFromProcessName(string processName)
    {
        var processes = Process.GetProcesses();

        var bestMatch = processes
            .Where(p => p.ProcessName.Contains(processName, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => LevenshteinDistance.Calculate(p.ProcessName, processName))
            .FirstOrDefault();

        return bestMatch?.Id;
    }

    #endregion

}