// =============================================================================
// PatternScanner.cs - Pattern Scanning for Internal Windows Functions
// =============================================================================
//
// This module finds internal (non-exported) Windows functions by scanning
// for known byte patterns. This is necessary for functions like
// LdrpHandleTlsData which are not exported but required for CRT support.
//
// LDRPHANDLETLSDATA EXPLAINED:
// ----------------------------
// LdrpHandleTlsData is an internal ntdll function that initializes TLS
// (Thread Local Storage) for a module. When Windows loads a DLL normally,
// the loader calls this function automatically. For manually mapped DLLs,
// we must call it ourselves, otherwise CRT DLLs will crash.
//
// The function's signature changed across Windows versions:
//
// Windows 8.1 - 11 22H2:
//   NTSTATUS LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY* LdrEntry)
//
// Windows 11 25H2+:
//   NTSTATUS LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY* LdrEntry, BOOLEAN Unknown)
//   The second parameter should be TRUE (1).
//
// PATTERN MATCHING STRATEGY:
// We search for known byte sequences at the start of the function.
// Different Windows versions have different function prologues.
// Patterns are tried in order of newest to oldest.
//
// MAINTENANCE NOTES:
// - When a new Windows version is released, check if patterns still work
// - Use IDA/Ghidra to find new patterns: search for "TlsIndex" references
// - The pattern should be unique enough to not match other functions
// - Test thoroughly - wrong pattern = crash or STATUS_RESOURCE_DATA_NOT_FOUND
// =============================================================================

using System.Runtime.InteropServices;
using Serilog;

namespace ManualImageMapper.Interop;

/// <summary>
/// Scans for internal Windows functions using byte patterns.
/// This is necessary for functions that are not exported but required
/// for proper DLL initialization (like LdrpHandleTlsData for TLS/CRT support).
/// </summary>
public static class PatternScanner
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(PatternScanner));

    /// <summary>
    /// Finds the offset of LdrpHandleTlsData within ntdll.dll.
    ///
    /// WHY WE NEED THIS:
    /// LdrpHandleTlsData initializes Thread Local Storage for a module.
    /// CRT DLLs use TLS extensively (for errno, thread-local state, etc.).
    /// Without calling this function, CRT initialization crashes.
    ///
    /// HOW TO UPDATE FOR NEW WINDOWS VERSIONS:
    /// 1. Open ntdll.dll in IDA/Ghidra
    /// 2. Search for "TlsIndex" or look for functions accessing TLS directory
    /// 3. Find LdrpHandleTlsData and note its function prologue bytes
    /// 4. Add a new pattern entry with appropriate offset
    /// </summary>
    /// <returns>Offset from ntdll base, or -1 if not found.</returns>
    public static int FindLdrpHandleTlsDataOffset()
    {
        var ntdll = NativeMethods.GetModuleHandle("ntdll.dll");
        if (ntdll == nint.Zero) return -1;

        // Get ntdll module info
        if (!NativeMethods.GetModuleInformation(
            NativeMethods.GetCurrentProcess(),
            ntdll,
            out var modInfo,
            (uint)Marshal.SizeOf<Structures.MODULEINFO>()))
        {
            return -1;
        }

        // Read ntdll into local memory for pattern scanning
        var ntdllBytes = new byte[modInfo.SizeOfImage];
        if (!NativeMethods.ReadProcessMemory(
            NativeMethods.GetCurrentProcess(),
            ntdll,
            ntdllBytes,
            ntdllBytes.Length,
            out _))
        {
            return -1;
        }

        // Try patterns in order (newest Windows version first)
        foreach (var (pattern, offset, name) in GetLdrpHandleTlsDataPatterns())
        {
            int idx = FindPattern(ntdllBytes, pattern);
            if (idx != -1)
            {
                int funcOffset = idx - offset;
                Log.Debug("Found LdrpHandleTlsData via {Pattern} at offset 0x{Offset:X}", name, funcOffset);
                return funcOffset;
            }
        }

        Log.Warning("Failed to find LdrpHandleTlsData - TLS initialization will be skipped");
        return -1;
    }

    /// <summary>
    /// Returns all known patterns for LdrpHandleTlsData, newest first.
    ///
    /// PATTERN FORMAT:
    /// - byte[] pattern: The bytes to search for
    /// - int offset: How far into the function the pattern appears
    /// - string name: Human-readable name for logging
    ///
    /// WINDOWS VERSION HISTORY:
    /// - Win11 25H2+: New 2-parameter version, different prologue
    /// - Win11 21H2-24H2: Standard prologue with 0xF0 stack frame
    /// - Win10 19H1+: Different prologue with TLS directory check
    /// - Win10 RS3-RS4: Earlier variant
    /// </summary>
    private static (byte[] pattern, int offset, string name)[] GetLdrpHandleTlsDataPatterns()
    {
        return
        [
            // =====================================================================
            // Windows 11 25H2+ (Build 26xxx)
            // Function now takes 2 parameters: (LDR_DATA_TABLE_ENTRY*, BOOLEAN)
            //
            // Pattern: mov r11, rsp; mov [r11+10h], rbx; mov [r11+18h], rsi; push rdi...
            // This is the function START - offset is 0
            //
            // If this pattern stops working in future builds:
            // 1. Load ntdll.dll in IDA
            // 2. Find LdrpHandleTlsData (search for TlsIndex references)
            // 3. Copy first ~24 unique bytes of function prologue
            // =====================================================================
            (
                new byte[] { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x10, 0x49, 0x89, 0x73, 0x18,
                             0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x00 },
                0,
                "Win11 25H2+"
            ),

            // =====================================================================
            // Windows 11 21H2 - 24H2 (Builds 22xxx-26xxx before 25H2)
            // Single parameter version
            //
            // Pattern appears at offset 0xF into the function
            // Pattern: push r13; push r14; push r15; sub rsp, 0xF0
            // =====================================================================
            (
                new byte[] { 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xF0, 0x00, 0x00 },
                0xF,
                "Win11 22H2+"
            ),

            // =====================================================================
            // Windows 10 19H1+ (Build 18xxx+)
            // Pattern includes TLS directory index check (9 = TLS directory)
            //
            // jz +0x33; lea r8d, [rbx+9]
            // The +9 is the TLS directory index in the PE data directories
            // =====================================================================
            (
                new byte[] { 0x74, 0x33, 0x44, 0x8D, 0x43, 0x09 },
                0x46,
                "Win10 19H1+"
            ),

            // =====================================================================
            // Windows 10 RS3-RS4 (Builds 16xxx-17xxx)
            // Earlier pattern variant
            // =====================================================================
            (
                new byte[] { 0x44, 0x8D, 0x43, 0x09, 0x4C, 0x8D, 0x4C, 0x24, 0x38 },
                0x43,
                "Win10 RS3+"
            ),
        ];
    }

    /// <summary>
    /// Simple pattern search in byte array.
    /// </summary>
    /// <param name="data">Data to search in.</param>
    /// <param name="pattern">Pattern to find.</param>
    /// <returns>Index of first match, or -1 if not found.</returns>
    private static int FindPattern(byte[] data, byte[] pattern)
    {
        for (int i = 0; i <= data.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    /// <summary>
    /// Builds a stub that calls LdrpHandleTlsData and stores the result.
    ///
    /// STUB BEHAVIOR:
    /// 1. Sets up stack frame with shadow space
    /// 2. Loads LDR_DATA_TABLE_ENTRY* into RCX (first param)
    /// 3. Loads 1 into DL (second param - needed for Win11 25H2+, ignored on older)
    /// 4. Calls LdrpHandleTlsData
    /// 5. Stores NTSTATUS result to resultPtr
    /// 6. Returns
    ///
    /// RETURN VALUES:
    /// - STATUS_SUCCESS (0): TLS initialized successfully
    /// - STATUS_RESOURCE_DATA_NOT_FOUND (0xC0000089): No TLS data in module (OK)
    /// - Other: Something went wrong
    /// </summary>
    /// <param name="ldrpHandleTlsData">Address of LdrpHandleTlsData in remote process.</param>
    /// <param name="ldrEntryPtr">Address of LDR_DATA_TABLE_ENTRY in remote process.</param>
    /// <param name="resultPtr">Address to store NTSTATUS result.</param>
    /// <returns>Stub bytes to execute in remote process.</returns>
    public static byte[] BuildLdrpHandleTlsDataStub(ulong ldrpHandleTlsData, ulong ldrEntryPtr, ulong resultPtr)
    {
        var b = new List<byte>();
        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            var prefix = reg < 8 ? 0x48 : 0x49;
            var opcode = reg < 8 ? (byte)(0xB8 + reg) : (byte)(0xB8 + (reg - 8));
            Emit((byte)prefix, (byte)opcode);
            Emit(BitConverter.GetBytes(imm));
        }

        // sub rsp, 0x28 (shadow space + alignment)
        Emit(0x48, 0x83, 0xEC, 0x28);

        // mov rcx, ldrEntryPtr (first argument)
        MovRegImm64(1, ldrEntryPtr);

        // mov dl, 1 (second argument - BOOLEAN = true)
        // Required for Win11 25H2+, safely ignored on older versions
        Emit(0xB2, 0x01);

        // mov rax, ldrpHandleTlsData
        MovRegImm64(0, ldrpHandleTlsData);

        // call rax (result in EAX)
        Emit(0xFF, 0xD0);

        // Store result: mov rcx, resultPtr; mov [rcx], eax
        MovRegImm64(1, resultPtr);
        Emit(0x89, 0x01);

        // add rsp, 0x28
        Emit(0x48, 0x83, 0xC4, 0x28);

        // ret
        Emit(0xC3);

        return [.. b];
    }
}
