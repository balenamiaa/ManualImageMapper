using System.Runtime.InteropServices;
using Serilog;

namespace ManualImageMapper.Interop;

/// <summary>
/// Pattern definitions for finding non-exported ntdll functions.
/// </summary>
public static class NtdllPatterns
{
    /// <summary>
    /// Represents a byte pattern for locating a function by its prologue.
    /// </summary>
    /// <param name="Bytes">Byte sequence to match.</param>
    /// <param name="Offset">Distance from pattern match to function entry.</param>
    /// <param name="Name">Pattern identifier for logging.</param>
    /// <param name="Priority">Search order (lower = tried first).</param>
    public readonly record struct Pattern(byte[] Bytes, int Offset, string Name, int Priority);

    /// <summary>
    /// LdrpHandleTlsData patterns for x64 Windows.
    /// Signatures vary by version:
    ///   Win8.1-11 24H2: NTSTATUS LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY*)
    ///   Win11 25H2+:    NTSTATUS LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY*, BOOLEAN)
    /// </summary>
    public static readonly Pattern[] LdrpHandleTlsData =
    [
        // Windows 11 25H2+ - verified
        new([0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x10, 0x49, 0x89, 0x73, 0x18,
             0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x00],
            Offset: 0, Name: "Win11 25H2+", Priority: 0),

        // Windows 11 21H2-24H2
        new([0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xF0, 0x00, 0x00],
            Offset: 0xF, Name: "Win11 22H2", Priority: 10),

        // Windows 10 19H1+
        new([0x74, 0x33, 0x44, 0x8D, 0x43, 0x09],
            Offset: 0x46, Name: "Win10 19H1+", Priority: 20),

        // Windows 10 RS3-RS4
        new([0x44, 0x8D, 0x43, 0x09, 0x4C, 0x8D, 0x4C, 0x24, 0x38],
            Offset: 0x43, Name: "Win10 RS3+", Priority: 30),
    ];
}

/// <summary>
/// Scans ntdll.dll for non-exported functions using byte patterns.
/// </summary>
public static class PatternScanner
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(PatternScanner));
    private static byte[]? _ntdllBytes;
    private static readonly object _ntdllLock = new();

    /// <summary>
    /// Finds LdrpHandleTlsData offset in ntdll.dll.
    /// </summary>
    public static int FindLdrpHandleTlsDataOffset()
        => FindFunctionOffset(NtdllPatterns.LdrpHandleTlsData, "LdrpHandleTlsData");

    /// <summary>
    /// Builds a stub that calls LdrpHandleTlsData and stores the NTSTATUS result.
    /// </summary>
    /// <param name="ldrpHandleTlsData">Address of LdrpHandleTlsData in remote process.</param>
    /// <param name="ldrEntryPtr">Address of LDR_DATA_TABLE_ENTRY in remote process.</param>
    /// <param name="resultPtr">Address to store NTSTATUS result.</param>
    public static byte[] BuildLdrpHandleTlsDataStub(ulong ldrpHandleTlsData, ulong ldrEntryPtr, ulong resultPtr)
    {
        var b = new List<byte>();

        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            Emit(reg < 8 ? (byte)0x48 : (byte)0x49, (byte)(0xB8 + (reg & 7)));
            Emit(BitConverter.GetBytes(imm));
        }

        Emit(0x48, 0x83, 0xEC, 0x28);           // sub rsp, 0x28
        MovRegImm64(1, ldrEntryPtr);            // mov rcx, ldrEntryPtr
        Emit(0xB2, 0x01);                       // mov dl, 1 (for Win11 25H2+)
        MovRegImm64(0, ldrpHandleTlsData);      // mov rax, ldrpHandleTlsData
        Emit(0xFF, 0xD0);                       // call rax
        MovRegImm64(1, resultPtr);              // mov rcx, resultPtr
        Emit(0x89, 0x01);                       // mov [rcx], eax
        Emit(0x48, 0x83, 0xC4, 0x28);           // add rsp, 0x28
        Emit(0xC3);                             // ret

        return [.. b];
    }

    private static int FindFunctionOffset(NtdllPatterns.Pattern[] patterns, string functionName)
    {
        var ntdllBytes = GetNtdllBytes();
        if (ntdllBytes == null)
        {
            Log.Warning("Failed to read ntdll.dll for pattern scanning");
            return -1;
        }

        foreach (var pattern in patterns.OrderBy(p => p.Priority))
        {
            int idx = FindPattern(ntdllBytes, pattern.Bytes);
            if (idx != -1)
            {
                int funcOffset = idx - pattern.Offset;
                Log.Debug("Found {Function} via pattern '{Pattern}' at offset 0x{Offset:X}",
                    functionName, pattern.Name, funcOffset);
                return funcOffset;
            }
        }

        Log.Warning("Failed to find {Function} - tried {Count} patterns", functionName, patterns.Length);
        return -1;
    }

    private static byte[]? GetNtdllBytes()
    {
        lock (_ntdllLock)
        {
            if (_ntdllBytes != null) return _ntdllBytes;

            var ntdll = NativeMethods.GetModuleHandle("ntdll.dll");
            if (ntdll == nint.Zero) return null;

            if (!NativeMethods.GetModuleInformation(
                NativeMethods.GetCurrentProcess(),
                ntdll,
                out var modInfo,
                (uint)Marshal.SizeOf<Structures.MODULEINFO>()))
            {
                return null;
            }

            var bytes = new byte[modInfo.SizeOfImage];
            if (!NativeMethods.ReadProcessMemory(
                NativeMethods.GetCurrentProcess(),
                ntdll,
                bytes,
                bytes.Length,
                out _))
            {
                return null;
            }

            _ntdllBytes = bytes;
            return _ntdllBytes;
        }
    }

    private static int FindPattern(byte[] data, byte[] pattern)
    {
        for (int i = 0; i <= data.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length && match; j++)
                match = data[i + j] == pattern[j];

            if (match) return i;
        }
        return -1;
    }
}
