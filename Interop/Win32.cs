// =============================================================================
// Win32.cs - Unified Windows Interop Facade
// =============================================================================
//
// This file serves as the main entry point for all Windows interop functionality.
// It re-exports types and methods from the modular files for backward compatibility
// and convenience.
//
// MODULE ORGANIZATION:
// -------------------
// The interop layer is split into focused modules:
//
// - NativeMethods.cs   : P/Invoke declarations (all Windows API calls)
// - Structures.cs      : PE format and Windows data structures
// - Constants.cs       : All constants and magic numbers
// - Helpers.cs         : Memory, process, module, and thread helpers
// - ExportResolver.cs  : DLL export resolution with forwarding support
// - PatternScanner.cs  : Finding internal Windows functions by pattern
// - PebLinker.cs       : PEB integration for CRT/TLS support
//
// USAGE:
// ------
// You can either:
// 1. Import this file: using static ManualImageMapper.Interop.Win32;
// 2. Import specific modules: using ManualImageMapper.Interop;
//
// MAINTENANCE:
// -----------
// When adding new functionality:
// 1. Add to the appropriate module (not here)
// 2. Re-export here if needed for backward compatibility
// 3. Update this header comment if adding new modules
// =============================================================================

using System.Runtime.InteropServices;

namespace ManualImageMapper.Interop;

/// <summary>
/// Unified Windows interop layer.
/// Re-exports from modular files for convenience and backward compatibility.
/// </summary>
public static partial class Win32
{
    // =========================================================================
    // RE-EXPORTED CONSTANTS
    // For code that uses: Win32.Const.PAGE_READWRITE
    // =========================================================================

    /// <summary>
    /// All constants used by the manual mapper.
    /// </summary>
    public static class Const
    {
        // Debug Markers
        public const ulong DEBUG_MARKER_INITIAL = Constants.DEBUG_MARKER_INITIAL;
        public const ulong DEBUG_MARKER_ENTRY = Constants.DEBUG_MARKER_ENTRY;
        public const ulong DEBUG_MARKER_PRE_DLLMAIN = Constants.DEBUG_MARKER_PRE_DLLMAIN;
        public const ulong DEBUG_MARKER_POST_DLLMAIN = Constants.DEBUG_MARKER_POST_DLLMAIN;

        // PE Format
        public const ulong IMAGE_ORDINAL_FLAG64 = Constants.IMAGE_ORDINAL_FLAG64;
        public const ulong IMAGE_THUNK_RVA_MASK64 = Constants.IMAGE_THUNK_RVA_MASK64;

        // Safety Limits
        public const int MAX_TLS_CALLBACKS = Constants.MAX_TLS_CALLBACKS;
        public const int MAX_PEB_LIST_ITERATIONS = Constants.MAX_PEB_LIST_ITERATIONS;
        public const int DLL_LOAD_WAIT_MS = Constants.DLL_LOAD_WAIT_MS;
        public const ulong DEFAULT_MODULE_SIZE_FALLBACK = Constants.DEFAULT_MODULE_SIZE_FALLBACK;

        // PEB Offsets
        public const int PEB_LDR_OFFSET = Constants.PEB_LDR_OFFSET;
        public const int LDR_IN_LOAD_ORDER_OFFSET = Constants.LDR_IN_LOAD_ORDER_OFFSET;
        public const int LDR_ENTRY_DLLBASE_OFFSET = Constants.LDR_ENTRY_DLLBASE_OFFSET;
        public const int LDR_ENTRY_IN_LOAD_OFFSET = Constants.LDR_ENTRY_IN_LOAD_OFFSET;
        public const int LDR_ENTRY_IN_MEMORY_OFFSET = Constants.LDR_ENTRY_IN_MEMORY_OFFSET;
        public const int LDR_ENTRY_IN_INIT_OFFSET = Constants.LDR_ENTRY_IN_INIT_OFFSET;

        // PE Signatures
        public const ushort IMAGE_DOS_SIGNATURE = Constants.IMAGE_DOS_SIGNATURE;
        public const uint IMAGE_NT_SIGNATURE = Constants.IMAGE_NT_SIGNATURE;
        public const int IMAGE_REL_BASED_DIR64 = Constants.IMAGE_REL_BASED_DIR64;

        // Memory
        public const uint PROCESS_ALL_ACCESS = Constants.PROCESS_ALL_ACCESS;
        public const uint MEM_COMMIT = Constants.MEM_COMMIT;
        public const uint MEM_RESERVE = Constants.MEM_RESERVE;
        public const uint MEM_RELEASE = Constants.MEM_RELEASE;

        // Page Protection
        public const uint PAGE_NOACCESS = Constants.PAGE_NOACCESS;
        public const uint PAGE_READONLY = Constants.PAGE_READONLY;
        public const uint PAGE_READWRITE = Constants.PAGE_READWRITE;
        public const uint PAGE_EXECUTE = Constants.PAGE_EXECUTE;
        public const uint PAGE_EXECUTE_READ = Constants.PAGE_EXECUTE_READ;
        public const uint PAGE_EXECUTE_READWRITE = Constants.PAGE_EXECUTE_READWRITE;

        // Thread
        public const uint INFINITE = Constants.INFINITE;
        public const uint DLL_PROCESS_ATTACH = Constants.DLL_PROCESS_ATTACH;
        public const uint TOKEN_ADJUST_PRIVILEGES = Constants.TOKEN_ADJUST_PRIVILEGES;
        public const uint TOKEN_QUERY = Constants.TOKEN_QUERY;
        public const uint SE_PRIVILEGE_ENABLED = Constants.SE_PRIVILEGE_ENABLED;
        public const string SE_DEBUG_NAME = Constants.SE_DEBUG_NAME;
        public const uint THREAD_ALL_ACCESS = Constants.THREAD_ALL_ACCESS;
        public const uint CONTEXT_ALL = Constants.CONTEXT_ALL;
        public const uint TH32CS_SNAPTHREAD = Constants.TH32CS_SNAPTHREAD;
        public const uint TH32CS_SNAPMODULE = Constants.TH32CS_SNAPMODULE;
        public const uint TH32CS_SNAPMODULE32 = Constants.TH32CS_SNAPMODULE32;
    }

    // =========================================================================
    // RE-EXPORTED P/INVOKE (for backward compatibility)
    // =========================================================================

    public static nint OpenProcess(uint access, bool inherit, int pid) =>
        NativeMethods.OpenProcess(access, inherit, pid);

    public static bool CloseHandle(nint handle) =>
        NativeMethods.CloseHandle(handle);

    public static nint GetProcAddress(nint hModule, string procName) =>
        NativeMethods.GetProcAddress(hModule, procName);

    public static nint GetModuleHandle(string? moduleName) =>
        NativeMethods.GetModuleHandle(moduleName);

    public static nint VirtualAllocEx(nint hProcess, nint address, uint size, uint allocType, uint protect) =>
        NativeMethods.VirtualAllocEx(hProcess, address, size, allocType, protect);

    public static bool VirtualFreeEx(nint hProcess, nint address, int size, uint freeType) =>
        NativeMethods.VirtualFreeEx(hProcess, address, size, freeType);

    public static bool WriteProcessMemory(nint hProcess, nint baseAddr, byte[] buffer, uint size, out nint bytesWritten) =>
        NativeMethods.WriteProcessMemory(hProcess, baseAddr, buffer, size, out bytesWritten);

    public static bool ReadProcessMemory(nint hProcess, nint baseAddr, byte[] buffer, int size, out nint bytesRead) =>
        NativeMethods.ReadProcessMemory(hProcess, baseAddr, buffer, size, out bytesRead);

    public static nint CreateRemoteThread(nint hProcess, nint attr, uint stackSize, nint startAddr, nint param, uint flags, nint threadId) =>
        NativeMethods.CreateRemoteThread(hProcess, attr, stackSize, startAddr, param, flags, threadId);

    public static uint WaitForSingleObject(nint handle, uint milliseconds) =>
        NativeMethods.WaitForSingleObject(handle, milliseconds);

    public static bool VirtualProtectEx(nint hProcess, nint address, uint size, uint newProtect, out uint oldProtect) =>
        NativeMethods.VirtualProtectEx(hProcess, address, size, newProtect, out oldProtect);

    public static int NtQueryInformationProcess(nint handle, Structures.PROCESSINFOCLASS infoClass, out Structures.PROCESS_BASIC_INFORMATION info, int infoLen, out int returnLen) =>
        NativeMethods.NtQueryInformationProcess(handle, infoClass, out info, infoLen, out returnLen);

    public static nint GetCurrentProcess() => NativeMethods.GetCurrentProcess();

    public static bool PostThreadMessage(uint threadId, uint msg, nuint wParam, nint lParam) =>
        NativeMethods.PostThreadMessage(threadId, msg, wParam, lParam);

    public static uint NtAlertThread(nint hThread) => NativeMethods.NtAlertThread(hThread);

    public static nint OpenThread(uint access, bool inherit, uint threadId) =>
        NativeMethods.OpenThread(access, inherit, threadId);

    public static uint SuspendThread(nint hThread) => NativeMethods.SuspendThread(hThread);
    public static uint ResumeThread(nint hThread) => NativeMethods.ResumeThread(hThread);

    public static bool FlushInstructionCache(nint hProcess, nint baseAddr, nuint size) =>
        NativeMethods.FlushInstructionCache(hProcess, baseAddr, size);

    public static nint CreateToolhelp32Snapshot(uint flags, uint processId) =>
        NativeMethods.CreateToolhelp32Snapshot(flags, processId);

    public static bool Thread32First(nint hSnapshot, ref Structures.THREADENTRY32 entry) =>
        NativeMethods.Thread32First(hSnapshot, ref entry);

    public static bool Thread32Next(nint hSnapshot, ref Structures.THREADENTRY32 entry) =>
        NativeMethods.Thread32Next(hSnapshot, ref entry);

    public static bool Module32First(nint hSnapshot, ref Structures.MODULEENTRY32W entry) =>
        NativeMethods.Module32First(hSnapshot, ref entry);

    public static bool Module32Next(nint hSnapshot, ref Structures.MODULEENTRY32W entry) =>
        NativeMethods.Module32Next(hSnapshot, ref entry);

    public static bool GetModuleInformation(nint hProcess, nint hModule, out Structures.MODULEINFO info, uint cb) =>
        NativeMethods.GetModuleInformation(hProcess, hModule, out info, cb);

    // =========================================================================
    // RE-EXPORTED HELPER METHODS
    // =========================================================================

    public static nint OpenTargetProcess(int pid) => MemoryHelpers.OpenTargetProcess(pid);
    public static void CloseHandleSafe(nint handle) => MemoryHelpers.CloseHandleSafe(handle);
    public static nint AllocateMemory(nint hProcess, uint size, uint protection = Constants.PAGE_READWRITE) =>
        MemoryHelpers.AllocateMemory(hProcess, size, protection);
    public static void FreeMemory(nint hProcess, nint address) => MemoryHelpers.FreeMemory(hProcess, address);
    public static void WriteMemory(nint hProcess, nint baseAddress, byte[] data) =>
        MemoryHelpers.WriteMemory(hProcess, baseAddress, data);
    public static byte[] ReadMemory(nint hProcess, nint baseAddress, int size) =>
        MemoryHelpers.ReadMemory(hProcess, baseAddress, size);
    public static uint ProtectMemory(nint hProcess, nint address, uint size, uint newProtect) =>
        MemoryHelpers.ProtectMemory(hProcess, address, size, newProtect);
    public static nint CreateRemoteThreadAndWait(nint hProcess, nint startAddress, nint parameter, bool wait = true) =>
        MemoryHelpers.CreateRemoteThreadAndWait(hProcess, startAddress, parameter, wait);

    public static T BytesToStructure<T>(byte[] buffer, int offset = 0) where T : struct =>
        MemoryHelpers.BytesToStructure<T>(buffer, offset);
    public static byte[] StructureToBytes<T>(T structure) where T : struct =>
        MemoryHelpers.StructureToBytes(structure);

    public static nint GetRemoteModuleHandle(nint hProcess, int pid, string moduleName) =>
        ModuleHelpers.GetRemoteModuleHandle(hProcess, pid, moduleName);
    public static int? GetProcessIdFromProcessName(string processName) =>
        ModuleHelpers.GetProcessIdFromProcessName(processName);
    public static bool IsProcess64Bit(nint hProcess) => ModuleHelpers.IsProcess64Bit(hProcess);

    public static Structures.IMAGE_DOS_HEADER GetDosHeader(byte[] image) => PeHelpers.GetDosHeader(image);
    public static Structures.IMAGE_NT_HEADERS64 GetNtHeaders(byte[] image) => PeHelpers.GetNtHeaders(image);
    public static List<Structures.IMAGE_SECTION_HEADER> GetSectionHeaders(byte[] image) => PeHelpers.GetSectionHeaders(image);
    public static uint AlignUp(uint value, uint alignment) => PeHelpers.AlignUp(value, alignment);
    public static uint CharacteristicsToProtection(uint characteristics) => PeHelpers.CharacteristicsToProtection(characteristics);

    public static bool EnableSeDebugPrivilege() => PrivilegeHelpers.EnableSeDebugPrivilege();

    public static bool TryGetThreadContext(nint hThread, out Structures.CONTEXT64 context) =>
        ThreadHelpers.TryGetThreadContext(hThread, out context);
    public static bool TrySetThreadContext(nint hThread, in Structures.CONTEXT64 context) =>
        ThreadHelpers.TrySetThreadContext(hThread, context);

    // =========================================================================
    // RE-EXPORTED FROM SPECIALIZED MODULES
    // =========================================================================

    public static nint GetRemoteProcAddress(nint hProcess, nint moduleBase, string functionName, int pid = 0, int recursionDepth = 0) =>
        ExportResolver.GetRemoteProcAddress(hProcess, moduleBase, functionName, pid, recursionDepth);

    public static nint GetRemoteProcAddressByOrdinal(nint hProcess, nint moduleBase, ushort ordinal) =>
        ExportResolver.GetRemoteProcAddressByOrdinal(hProcess, moduleBase, ordinal);

    public static int FindLdrpHandleTlsDataOffset() => PatternScanner.FindLdrpHandleTlsDataOffset();

    public static nint LinkModuleToPEB(nint hProcess, int pid, nint moduleBase, uint sizeOfImage, nint entryPoint, ulong originalImageBase, string dllName, string fullDllPath) =>
        PebLinker.LinkModuleToPEB(hProcess, pid, moduleBase, sizeOfImage, entryPoint, originalImageBase, dllName, fullDllPath);

    public static nint InitializeCrtModule(nint hProcess, int pid, nint moduleBase, uint sizeOfImage, nint entryPoint, ulong originalImageBase, string dllName) =>
        PebLinker.InitializeCrtModule(hProcess, pid, moduleBase, sizeOfImage, entryPoint, originalImageBase, dllName);

    public static void UnlinkFromPEB(nint hProcess, nint moduleBase) =>
        PebLinker.UnlinkFromPEB(hProcess, moduleBase);

    public static uint ComputeModuleNameHash(string dllName) => PebLinker.ComputeModuleNameHash(dllName);

    // =========================================================================
    // SECTION MAPPING HELPER
    // =========================================================================

    public static void MapSections(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, IReadOnlyList<Structures.IMAGE_SECTION_HEADER> sections)
    {
        foreach (var section in sections)
        {
            var rawOffset = (int)section.PointerToRawData;
            var rawSize = (int)section.SizeOfRawData;
            if (rawSize == 0) continue;
            var slice = localImage.Slice(rawOffset, rawSize);
            var remoteAddress = remoteBase + (int)section.VirtualAddress;
            WriteMemory(hProcess, remoteAddress, slice.ToArray());
        }
    }

    public static void SetSectionProtections(nint hProcess, nint remoteBase, IReadOnlyList<Structures.IMAGE_SECTION_HEADER> sections)
    {
        foreach (var section in sections)
        {
            var size = AlignUp(section.VirtualSize, 0x1000);
            var prot = CharacteristicsToProtection(section.Characteristics);
            var remoteAddress = remoteBase + (int)section.VirtualAddress;
            ProtectMemory(hProcess, remoteAddress, size, prot);
        }
    }
}

