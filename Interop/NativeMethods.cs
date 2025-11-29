// =============================================================================
// NativeMethods.cs - Windows API P/Invoke Declarations
// =============================================================================
//
// This file contains all P/Invoke declarations for Windows API functions used
// by the manual mapper. Functions are organized by their source DLL.
//
// MAINTENANCE NOTES:
// - When adding new P/Invoke declarations, group them with their source DLL
// - Use LibraryImport (source-generated) for better performance where possible
// - Always set SetLastError = true for functions that use GetLastError
// =============================================================================

using System.Runtime.InteropServices;

namespace ManualImageMapper.Interop;

/// <summary>
/// P/Invoke declarations for Windows API functions.
/// All functions are organized by their source DLL for easy maintenance.
/// </summary>
public static partial class NativeMethods
{
    #region kernel32.dll - Process and Memory Management

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial nint GetProcAddress(nint hModule, string procName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint GetProcAddress(nint hModule, nint ordinal);

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleHandleA", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial nint GetModuleHandle(string? lpModuleName);

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

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool FlushInstructionCache(nint hProcess, nint lpBaseAddress, nuint dwSize);

    #endregion

    #region kernel32.dll - Thread Management

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint SuspendThread(nint hThread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint ResumeThread(nint hThread);

    [LibraryImport("kernel32.dll", EntryPoint = "GetThreadContext", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetThreadContextRaw(nint hThread, nint lpContext);

    [LibraryImport("kernel32.dll", EntryPoint = "SetThreadContext", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetThreadContextRaw(nint hThread, nint lpContext);

    #endregion

    #region kernel32.dll - Toolhelp Snapshots

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Thread32First(nint hSnapshot, ref Structures.THREADENTRY32 lpte);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Thread32Next(nint hSnapshot, ref Structures.THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "Module32FirstW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Module32First(nint hSnapshot, ref Structures.MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "Module32NextW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Module32Next(nint hSnapshot, ref Structures.MODULEENTRY32W lpme);

    #endregion

    #region kernel32.dll - Architecture Detection

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "IsWow64Process2")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool IsWow64Process2(nint hProcess, out ushort processMachine, out ushort nativeMachine);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool IsWow64Process(nint hProcess, [MarshalAs(UnmanagedType.Bool)] out bool isWow64);

    #endregion

    #region ntdll.dll - NT Native API

    [LibraryImport("ntdll.dll")]
    public static partial int NtQueryInformationProcess(
        nint ProcessHandle,
        Structures.PROCESSINFOCLASS ProcessInformationClass,
        out Structures.PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength);

    [LibraryImport("ntdll.dll")]
    public static partial uint NtAlertThread(nint hThread);

    [LibraryImport("ntdll.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool RtlAddFunctionTable(nint FunctionTable, uint EntryCount, ulong BaseAddress);

    #endregion

    #region advapi32.dll - Security and Privileges

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess, out nint TokenHandle);

    [LibraryImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueA", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool AdjustTokenPrivileges(
        nint TokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        ref Structures.TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        nint PreviousState,
        nint ReturnLength);

    #endregion

    #region user32.dll - Window Messages

    [LibraryImport("user32.dll", SetLastError = true, EntryPoint = "PostThreadMessageW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PostThreadMessage(uint idThread, uint msg, nuint wParam, nint lParam);

    #endregion

    #region psapi.dll - Process Status API

    [LibraryImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetModuleInformation(nint hProcess, nint hModule, out Structures.MODULEINFO lpmodinfo, uint cb);

    #endregion
}
