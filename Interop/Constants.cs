namespace ManualImageMapper.Interop;

/// <summary>
/// All constants used by the manual mapper.
/// Organized by functional category.
/// </summary>
public static class Constants
{
    // =========================================================================
    // DEBUG MARKERS
    // Used to track execution progress when debug mode is enabled.
    // The loader stub writes these values at each stage.
    // =========================================================================

    /// <summary>Initial value before stub executes.</summary>
    public const ulong DEBUG_MARKER_INITIAL = 0xDEADBEEFCAFEBABE;

    /// <summary>Written when stub begins executing.</summary>
    public const ulong DEBUG_MARKER_ENTRY = 0x1111111111111111;

    /// <summary>Written after TLS callbacks complete.</summary>
    public const ulong DEBUG_MARKER_POST_TLS = 0x3333333333333333;

    /// <summary>Written just before calling DllMain.</summary>
    public const ulong DEBUG_MARKER_PRE_DLLMAIN = 0x2222222222222222;

    /// <summary>Written after DllMain returns successfully.</summary>
    public const ulong DEBUG_MARKER_POST_DLLMAIN = 0x1337DEADBEEFCAFE;

    /// <summary>Written after DotnetMain returns successfully.</summary>
    public const ulong DEBUG_MARKER_POST_DOTNETMAIN = 0x4444444444444444;

    // =========================================================================
    // PE FORMAT CONSTANTS
    // Magic numbers and flags from the PE specification.
    // =========================================================================

    /// <summary>DOS header magic ("MZ").</summary>
    public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;

    /// <summary>PE signature ("PE\0\0").</summary>
    public const uint IMAGE_NT_SIGNATURE = 0x00004550;

    /// <summary>Relocation type for 64-bit absolute addresses.</summary>
    public const int IMAGE_REL_BASED_DIR64 = 10;

    /// <summary>Flag indicating import by ordinal (high bit set).</summary>
    public const ulong IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;

    /// <summary>Mask to extract RVA from import thunk (clear high bit).</summary>
    public const ulong IMAGE_THUNK_RVA_MASK64 = 0x7FFFFFFFFFFFFFFF;

    // =========================================================================
    // PROCESS ACCESS RIGHTS
    // =========================================================================

    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

    // =========================================================================
    // MEMORY ALLOCATION
    // =========================================================================

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;

    // =========================================================================
    // PAGE PROTECTION
    // =========================================================================

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    // =========================================================================
    // WAIT/TIMEOUT
    // =========================================================================

    public const uint INFINITE = 0xFFFFFFFF;

    // =========================================================================
    // DLL NOTIFICATION REASONS
    // =========================================================================

    public const uint DLL_PROCESS_ATTACH = 1;

    // =========================================================================
    // TOKEN/PRIVILEGE CONSTANTS
    // For enabling SeDebugPrivilege.
    // =========================================================================

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public const string SE_DEBUG_NAME = "SeDebugPrivilege";

    // =========================================================================
    // THREAD CONSTANTS
    // =========================================================================

    public const uint THREAD_ALL_ACCESS = 0x1FFFFF;

    // x64 CONTEXT flags
    public const uint CONTEXT_AMD64 = 0x00100000;
    public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
    public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
    public const uint CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
    public const uint CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
    public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
    public const uint CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                                    CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

    // Toolhelp snapshot flags
    public const uint TH32CS_SNAPTHREAD = 0x00000004;
    public const uint TH32CS_SNAPMODULE = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;

    // =========================================================================
    // PEB/LDR OFFSETS (Windows 10/11 x64)
    // These offsets may differ on other Windows versions!
    // =========================================================================

    /// <summary>Offset of Ldr field in PEB structure.</summary>
    public const int PEB_LDR_OFFSET = 0x18;

    /// <summary>Offset of InLoadOrderModuleList in PEB_LDR_DATA.</summary>
    public const int LDR_IN_LOAD_ORDER_OFFSET = 0x10;

    /// <summary>Offset of DllBase in LDR_DATA_TABLE_ENTRY.</summary>
    public const int LDR_ENTRY_DLLBASE_OFFSET = 0x30;

    /// <summary>Offset of InLoadOrderLinks in LDR_DATA_TABLE_ENTRY.</summary>
    public const int LDR_ENTRY_IN_LOAD_OFFSET = 0x00;

    /// <summary>Offset of InMemoryOrderLinks in LDR_DATA_TABLE_ENTRY.</summary>
    public const int LDR_ENTRY_IN_MEMORY_OFFSET = 0x10;

    /// <summary>Offset of InInitializationOrderLinks in LDR_DATA_TABLE_ENTRY.</summary>
    public const int LDR_ENTRY_IN_INIT_OFFSET = 0x20;

    // =========================================================================
    // SAFETY LIMITS
    // Prevent infinite loops and runaway allocations.
    // =========================================================================

    /// <summary>Maximum TLS callbacks to process (prevent corruption issues).</summary>
    public const int MAX_TLS_CALLBACKS = 64;

    /// <summary>Maximum PEB list iterations (prevent infinite loops).</summary>
    public const int MAX_PEB_LIST_ITERATIONS = 512;

    /// <summary>Wait time for DLL load operations.</summary>
    public const int DLL_LOAD_WAIT_MS = 100;

    /// <summary>Fallback module size if GetModuleInformation fails.</summary>
    public const ulong DEFAULT_MODULE_SIZE_FALLBACK = 0x200000;

    /// <summary>Maximum export forwarder chain depth (prevent circular refs).</summary>
    public const int MAX_FORWARDER_DEPTH = 5;
}
