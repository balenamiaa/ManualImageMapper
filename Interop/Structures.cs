// =============================================================================
// Structures.cs - PE Format and Windows Data Structures
// =============================================================================
//
// This file contains all structure definitions used for PE parsing and Windows
// loader integration. Structures are organized into logical groups:
//
// 1. PE FORMAT STRUCTURES - For parsing PE headers (DOS, NT, sections, etc.)
// 2. IMPORT/EXPORT STRUCTURES - For resolving DLL imports and exports
// 3. TLS STRUCTURES - For Thread Local Storage support
// 4. LOADER STRUCTURES - For integrating with Windows loader (PEB, LDR)
// 5. THREAD STRUCTURES - For thread hijacking and context manipulation
// 6. MISC STRUCTURES - Process info, privileges, etc.
//
// MAINTENANCE NOTES:
// - All offsets are for Windows 10/11 x64. Earlier versions may differ.
// - When adding structures, include field offsets in comments for debugging.
// - Use [FieldOffset] for unions and structures with explicit layout.
// =============================================================================

using System.Runtime.InteropServices;

namespace ManualImageMapper.Interop;

/// <summary>
/// All structure definitions for PE parsing and Windows integration.
/// </summary>
public static class Structures
{
    // =========================================================================
    // PE FORMAT STRUCTURES
    // These structures mirror the PE (Portable Executable) file format.
    // Reference: Microsoft PE/COFF Specification
    // =========================================================================

    /// <summary>
    /// DOS Header - First structure in every PE file.
    /// The e_lfanew field points to the NT Headers.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;      // Must be 0x5A4D ("MZ")
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;        // Offset to NT Headers
    }

    /// <summary>
    /// COFF File Header - Contains basic file information.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public MachineType Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    /// <summary>
    /// Data Directory entry - Points to various PE data structures.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;  // RVA of the data
        public uint Size;            // Size of the data
    }

    /// <summary>
    /// Optional Header (64-bit) - Contains loader information.
    /// Despite its name, this header is required for executables.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public MagicType Magic;                    // Must be 0x20b for PE32+
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;           // RVA of entry point (DllMain for DLLs)
        public uint BaseOfCode;
        public ulong ImageBase;                    // Preferred load address
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;                   // Total size when loaded
        public uint SizeOfHeaders;
        public uint CheckSum;
        public SubSystemType Subsystem;
        public DllCharacteristicsType DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;  // Array of data directories
    }

    /// <summary>
    /// NT Headers (64-bit) - Main PE header structure.
    /// Located at DOS_HEADER.e_lfanew offset.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS64
    {
        public uint Signature;                     // Must be 0x00004550 ("PE\0\0")
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    /// <summary>
    /// Section Header - Describes a PE section (.text, .data, .rdata, etc.)
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string Name;
        public uint VirtualSize;        // Size in memory
        public uint VirtualAddress;     // RVA when loaded
        public uint SizeOfRawData;      // Size on disk
        public uint PointerToRawData;   // File offset
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;    // Section flags (executable, readable, writable)
    }

    /// <summary>
    /// Base Relocation Block - Header for a block of relocations.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAddress;     // Page RVA
        public uint SizeOfBlock;        // Total size including entries
    }

    // =========================================================================
    // IMPORT/EXPORT STRUCTURES
    // Used for resolving DLL dependencies and function addresses.
    // =========================================================================

    /// <summary>
    /// Import Descriptor - One per imported DLL.
    /// The import table is an array of these, terminated by an all-zero entry.
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        [FieldOffset(0)] public uint Characteristics;
        [FieldOffset(0)] public uint OriginalFirstThunk;  // RVA to INT (Import Name Table)
        [FieldOffset(4)] public uint TimeDateStamp;
        [FieldOffset(8)] public uint ForwarderChain;
        [FieldOffset(12)] public uint Name;               // RVA to DLL name string
        [FieldOffset(16)] public uint FirstThunk;         // RVA to IAT (Import Address Table)
    }

    /// <summary>
    /// Delay-Load Import Descriptor - For delay-loaded DLLs.
    /// These DLLs are loaded on first use rather than at startup.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DELAYLOAD_DESCRIPTOR
    {
        public uint Attributes;
        public uint DllNameRVA;
        public uint ModuleHandleRVA;
        public uint ImportAddressTableRVA;
        public uint ImportNameTableRVA;
        public uint BoundImportAddressTableRVA;
        public uint UnloadInformationTableRVA;
        public uint TimeDateStamp;
    }

    /// <summary>
    /// Export Directory - Contains information about exported functions.
    /// Used to resolve function addresses in remote processes.
    ///
    /// IMPORTANT: Export forwarding is handled specially. When a function's
    /// RVA points within the export directory itself, it's a forwarder string
    /// like "NTDLL.RtlInitializeSListHead" rather than actual code.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;                   // RVA to DLL name
        public uint Base;                   // Ordinal base (usually 1)
        public uint NumberOfFunctions;      // Total exported functions
        public uint NumberOfNames;          // Number of named exports
        public uint AddressOfFunctions;     // RVA to function address array
        public uint AddressOfNames;         // RVA to name RVA array
        public uint AddressOfNameOrdinals;  // RVA to ordinal array
    }

    /// <summary>
    /// Runtime Function Entry - For structured exception handling (SEH).
    /// Required for .NET AOT DLLs and any code using SEH.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RUNTIME_FUNCTION_ENTRY
    {
        public uint BeginAddress;
        public uint EndAddress;
        public uint UnwindInfoAddress;
    }

    // =========================================================================
    // TLS (THREAD LOCAL STORAGE) STRUCTURES
    // Required for CRT DLLs to properly initialize thread-local variables.
    // =========================================================================

    /// <summary>
    /// TLS Directory (64-bit) - Describes thread-local storage for the module.
    ///
    /// CRITICAL FOR CRT SUPPORT:
    /// - AddressOfIndex: Loader writes the TLS index here
    /// - AddressOfCallBacks: Array of TLS callback functions (null-terminated)
    /// - The loader calls LdrpHandleTlsData to initialize TLS for manually mapped modules
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY64
    {
        public ulong StartAddressOfRawData;   // VA of TLS template data start
        public ulong EndAddressOfRawData;     // VA of TLS template data end
        public ulong AddressOfIndex;          // VA where loader stores TLS index
        public ulong AddressOfCallBacks;      // VA of TLS callback array
        public uint SizeOfZeroFill;           // Size to zero-fill after template
        public uint Characteristics;
    }

    // =========================================================================
    // LOADER STRUCTURES (PEB/LDR)
    // Used to integrate manually mapped modules with Windows loader.
    // This is CRITICAL for CRT support - the CRT expects the module to be
    // registered in the loader's data structures.
    // =========================================================================

    /// <summary>
    /// UNICODE_STRING - Windows native string type.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    /// <summary>
    /// LIST_ENTRY - Doubly-linked list node.
    /// Used extensively in PEB/LDR structures.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct LIST_ENTRY
    {
        public nint Flink;  // Forward link
        public nint Blink;  // Backward link
    }

    /// <summary>
    /// RTL_BALANCED_NODE - Red-black tree node (Windows 8+).
    /// Used for fast module lookup by address.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct RTL_BALANCED_NODE
    {
        public nint Left;
        public nint Right;
        public nint ParentValue;  // Parent with balance encoded in low bits
    }

    /// <summary>
    /// LDR_DDAG_NODE - Module dependency tracking (Windows 8+).
    /// Part of the Directed Dependency Acyclic Graph for module loading.
    /// Size: 0x50 bytes on x64
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct LDR_DDAG_NODE
    {
        public LIST_ENTRY Modules;              // 0x00 - List of LDR_DATA_TABLE_ENTRY.NodeModuleLink
        public nint ServiceTagList;             // 0x10
        public uint LoadCount;                  // 0x18 - Reference count
        public uint LoadWhileUnloadingCount;    // 0x1C
        public uint LowestLink;                 // 0x20
        public uint Padding1;                   // 0x24
        public nint Dependencies;               // 0x28
        public nint IncomingDependencies;       // 0x30
        public LDR_DDAG_STATE State;            // 0x38 - Module loading state
        public uint Padding2;                   // 0x3C
        public nint CondenseLink;               // 0x40
        public uint PreorderNumber;             // 0x48
        public uint Padding3;                   // 0x4C
    }

    /// <summary>
    /// LDR_DATA_TABLE_ENTRY - Main loader structure for each loaded module.
    ///
    /// This is THE critical structure for CRT support. When we manually map a DLL,
    /// we must create this structure and link it into the PEB's module lists.
    /// Otherwise, the CRT's initialization code will fail because it expects
    /// the module to be registered with the loader.
    ///
    /// Size: ~0x120 bytes on Windows 10/11 x64
    ///
    /// WINDOWS VERSION COMPATIBILITY:
    /// - This structure layout is for Windows 10/11 x64
    /// - Earlier versions have different layouts
    /// - The TlsIndex field at offset 0x6E is critical for TLS support
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct LDR_DATA_TABLE_ENTRY
    {
        public LIST_ENTRY InLoadOrderLinks;               // 0x00 - Links in load order list
        public LIST_ENTRY InMemoryOrderLinks;             // 0x10 - Links in memory order list
        public LIST_ENTRY InInitializationOrderLinks;     // 0x20 - Links in init order list
        public nint DllBase;                              // 0x30 - Module base address
        public nint EntryPoint;                           // 0x38 - Entry point (DllMain)
        public uint SizeOfImage;                          // 0x40 - Size when loaded
        public uint Padding1;                             // 0x44
        public UNICODE_STRING FullDllName;                // 0x48 - Full path to DLL
        public UNICODE_STRING BaseDllName;                // 0x58 - Just the filename
        public uint Flags;                                // 0x68 - LdrFlags (see LdrFlags class)
        public ushort ObsoleteLoadCount;                  // 0x6C - Deprecated
        public ushort TlsIndex;                           // 0x6E - TLS index (0xFFFF if none)
        public LIST_ENTRY HashLinks;                      // 0x70 - Hash bucket links
        public uint TimeDateStamp;                        // 0x80
        public uint Padding2;                             // 0x84
        public nint EntryPointActivationContext;          // 0x88
        public nint Lock;                                 // 0x90
        public nint DdagNode;                             // 0x98 - Pointer to LDR_DDAG_NODE
        public LIST_ENTRY NodeModuleLink;                 // 0xA0
        public nint LoadContext;                          // 0xB0
        public nint ParentDllBase;                        // 0xB8
        public nint SwitchBackContext;                    // 0xC0
        public RTL_BALANCED_NODE BaseAddressIndexNode;    // 0xC8
        public RTL_BALANCED_NODE MappingInfoIndexNode;    // 0xE0
        public ulong OriginalBase;                        // 0xF8 - Original ImageBase
        public long LoadTime;                             // 0x100
        public uint BaseNameHashValue;                    // 0x108
        public LDR_DLL_LOAD_REASON LoadReason;            // 0x10C
        public uint ImplicitPathOptions;                  // 0x110
        public uint ReferenceCount;                       // 0x114
        public uint DependentLoadFlags;                   // 0x118
        public byte SigningLevel;                         // 0x11C
    }

    // =========================================================================
    // THREAD STRUCTURES
    // For thread hijacking and context manipulation.
    // =========================================================================

    /// <summary>
    /// Thread snapshot entry - Used with CreateToolhelp32Snapshot.
    /// </summary>
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

    /// <summary>
    /// Module snapshot entry - Used to enumerate modules in a process.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MODULEENTRY32W
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlsRefCount;
        public uint ProccntUsage;
        public nint modBaseAddr;
        public uint modBaseSize;
        public nint hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    /// <summary>
    /// x64 Thread Context - Complete CPU state for a 64-bit thread.
    /// Must be 16-byte aligned when used with Get/SetThreadContext.
    /// Size: 0x4D0 bytes
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Size = 0x4D0)]
    public unsafe struct CONTEXT64
    {
        [FieldOffset(0x00)] public ulong P1Home;
        [FieldOffset(0x08)] public ulong P2Home;
        [FieldOffset(0x10)] public ulong P3Home;
        [FieldOffset(0x18)] public ulong P4Home;
        [FieldOffset(0x20)] public ulong P5Home;
        [FieldOffset(0x28)] public ulong P6Home;
        [FieldOffset(0x30)] public uint ContextFlags;
        [FieldOffset(0x34)] public uint MxCsr;
        [FieldOffset(0x38)] public ushort SegCs;
        [FieldOffset(0x3A)] public ushort SegDs;
        [FieldOffset(0x3C)] public ushort SegEs;
        [FieldOffset(0x3E)] public ushort SegFs;
        [FieldOffset(0x40)] public ushort SegGs;
        [FieldOffset(0x42)] public ushort SegSs;
        [FieldOffset(0x44)] public uint EFlags;
        [FieldOffset(0x48)] public ulong Dr0;
        [FieldOffset(0x50)] public ulong Dr1;
        [FieldOffset(0x58)] public ulong Dr2;
        [FieldOffset(0x60)] public ulong Dr3;
        [FieldOffset(0x68)] public ulong Dr6;
        [FieldOffset(0x70)] public ulong Dr7;
        [FieldOffset(0x78)] public ulong Rax;
        [FieldOffset(0x80)] public ulong Rcx;
        [FieldOffset(0x88)] public ulong Rdx;
        [FieldOffset(0x90)] public ulong Rbx;
        [FieldOffset(0x98)] public ulong Rsp;
        [FieldOffset(0xA0)] public ulong Rbp;
        [FieldOffset(0xA8)] public ulong Rsi;
        [FieldOffset(0xB0)] public ulong Rdi;
        [FieldOffset(0xB8)] public ulong R8;
        [FieldOffset(0xC0)] public ulong R9;
        [FieldOffset(0xC8)] public ulong R10;
        [FieldOffset(0xD0)] public ulong R11;
        [FieldOffset(0xD8)] public ulong R12;
        [FieldOffset(0xE0)] public ulong R13;
        [FieldOffset(0xE8)] public ulong R14;
        [FieldOffset(0xF0)] public ulong R15;
        [FieldOffset(0xF8)] public ulong Rip;           // Instruction pointer
        [FieldOffset(0x100)] public fixed byte FltSave[512];
        [FieldOffset(0x300)] public fixed byte VectorRegister[26 * 16];
        [FieldOffset(0x4A0)] public ulong VectorControl;
        [FieldOffset(0x4A8)] public ulong DebugControl;
        [FieldOffset(0x4B0)] public ulong LastBranchToRip;
        [FieldOffset(0x4B8)] public ulong LastBranchFromRip;
        [FieldOffset(0x4C0)] public ulong LastExceptionToRip;
        [FieldOffset(0x4C8)] public ulong LastExceptionFromRip;
    }

    // =========================================================================
    // MISCELLANEOUS STRUCTURES
    // =========================================================================

    /// <summary>
    /// Process Basic Information - Returned by NtQueryInformationProcess.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public nint Reserved1;
        public nint PebBaseAddress;  // Address of the Process Environment Block
        public nint Reserved2_0;
        public nint Reserved2_1;
        public nint UniqueProcessId;
        public nint Reserved3;
    }

    /// <summary>
    /// Module Information - Returned by GetModuleInformation.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO
    {
        public nint lpBaseOfDll;
        public uint SizeOfImage;
        public nint EntryPoint;
    }

    /// <summary>
    /// Token Privileges - For enabling SeDebugPrivilege.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privilege;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    // =========================================================================
    // ENUMERATIONS
    // =========================================================================

    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0
    }

    /// <summary>
    /// LDR_DDAG_STATE - Module loading states.
    /// Our manually mapped modules should be set to LdrModulesReadyToRun.
    /// </summary>
    public enum LDR_DDAG_STATE : int
    {
        LdrModulesMerged = -5,
        LdrModulesInitError = -4,
        LdrModulesSnapError = -3,
        LdrModulesUnloaded = -2,
        LdrModulesUnloading = -1,
        LdrModulesPlaceHolder = 0,
        LdrModulesMapping = 1,
        LdrModulesMapped = 2,
        LdrModulesWaitingForDependencies = 3,
        LdrModulesSnapping = 4,
        LdrModulesSnapped = 5,
        LdrModulesCondensed = 6,
        LdrModulesReadyToInit = 7,
        LdrModulesInitializing = 8,
        LdrModulesReadyToRun = 9
    }

    /// <summary>
    /// LDR_DLL_LOAD_REASON - Why a DLL was loaded.
    /// </summary>
    public enum LDR_DLL_LOAD_REASON : uint
    {
        LoadReasonStaticDependency = 0,
        LoadReasonStaticForwarderDependency = 1,
        LoadReasonDynamicForwarderDependency = 2,
        LoadReasonDelayloadDependency = 3,
        LoadReasonDynamicLoad = 4,
        LoadReasonAsImageLoad = 5,
        LoadReasonAsDataLoad = 6,
        LoadReasonEnclavePrimary = 7,
        LoadReasonEnclaveDependency = 8,
        LoadReasonUnknown = 0xFFFFFFFF
    }

    public enum MachineType : ushort
    {
        IMAGE_FILE_MACHINE_AMD64 = 0x8664
    }

    public enum MagicType : ushort
    {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    }

    public enum SubSystemType : ushort
    {
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    }

    public enum DllCharacteristicsType : ushort
    {
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
        IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    }

    public enum SectionCharacteristics : uint
    {
        IMAGE_SCN_CNT_CODE = 0x00000020,
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
        IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
        IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
        IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
        IMAGE_SCN_MEM_SHARED = 0x10000000,
        IMAGE_SCN_MEM_EXECUTE = 0x20000000,
        IMAGE_SCN_MEM_READ = 0x40000000,
        IMAGE_SCN_MEM_WRITE = 0x80000000
    }

    public enum ImageDirectoryEntry
    {
        EXPORT = 0,
        IMPORT = 1,
        RESOURCE = 2,
        EXCEPTION = 3,
        SECURITY = 4,
        BASERELOC = 5,
        DEBUG = 6,
        ARCHITECTURE = 7,
        GLOBALPTR = 8,
        TLS = 9,
        LOAD_CONFIG = 10,
        BOUND_IMPORT = 11,
        IAT = 12,
        DELAY_IMPORT = 13,
        COM_DESCRIPTOR = 14
    }
}

/// <summary>
/// LDR_DATA_TABLE_ENTRY flags.
/// These flags control loader behavior for the module.
/// </summary>
public static class LdrFlags
{
    public const uint LDRP_PACKAGED_BINARY = 0x00000001;
    public const uint LDRP_STATIC_LINK = 0x00000002;
    public const uint LDRP_IMAGE_DLL = 0x00000004;
    public const uint LDRP_LOAD_IN_PROGRESS = 0x00001000;
    public const uint LDRP_UNLOAD_IN_PROGRESS = 0x00002000;
    public const uint LDRP_ENTRY_PROCESSED = 0x00004000;
    public const uint LDRP_ENTRY_INSERTED = 0x00008000;
    public const uint LDRP_CURRENT_LOAD = 0x00010000;
    public const uint LDRP_FAILED_BUILTIN_LOAD = 0x00020000;
    public const uint LDRP_DONT_CALL_FOR_THREADS = 0x00040000;
    public const uint LDRP_PROCESS_ATTACH_CALLED = 0x00080000;
    public const uint LDRP_DEBUG_SYMBOLS_LOADED = 0x00100000;
    public const uint LDRP_IMAGE_NOT_AT_BASE = 0x00200000;
    public const uint LDRP_COR_IMAGE = 0x00400000;
    public const uint LDRP_REDIRECTED = 0x10000000;
    public const uint LDRP_COMPAT_DATABASE_PROCESSED = 0x80000000;
}
