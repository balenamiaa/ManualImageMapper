using System.Runtime.InteropServices;

namespace ManualImageMapper;

public static partial class FFI
{
    #region PE Constants

    public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // "MZ"
    public const uint IMAGE_NT_SIGNATURE = 0x00004550; // "PE\0\0"

    public const int IMAGE_REL_BASED_DIR64 = 10;

    // Process / memory constants
    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    public const uint INFINITE = 0xFFFFFFFF;

    #endregion

    // Privilege constants
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public const string SE_DEBUG_NAME = "SeDebugPrivilege";
}