using System.Runtime.InteropServices;

namespace ManualImageMapper;

public static partial class FFI
{
    #region Thread / Toolhelp Constants

    public const uint THREAD_ALL_ACCESS = 0x1FFFFF; // slightly version-dependent, this works on modern Win10+
    public const uint CONTEXT_AMD64 = 0x00100000;
    public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
    public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
    public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER;

    public const uint TH32CS_SNAPTHREAD = 0x00000004;

    #endregion

    #region Thread Structures

    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    // A minimal x64 CONTEXT structure – contains only the fields we need (RIP + general regs)
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public uint ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;

        public ulong Rip;
        // The full CONTEXT has many more fields (XMM registers, etc.). They are omitted for brevity; Windows ignores absent fields if ContextFlags doesn't reference them.
    }
    #endregion

    #region Thread / Toolhelp Native Methods

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

    #endregion
}