using System.Runtime.InteropServices;

namespace ManualImageMapper;

public static partial class FFI
{
    #region Enums

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

    public static class DllReason
    {
        public const uint DLL_PROCESS_ATTACH = 1;
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

    #endregion
} 