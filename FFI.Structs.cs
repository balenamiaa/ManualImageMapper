using System.Runtime.InteropServices;

namespace ManualImageMapper;

public static partial class FFI
{
    #region Additional PE Structures

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_IMPORT_BY_NAME
    {
        public ushort Hint;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] // variable size
        public byte[] Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DELAY_IMPORT_DESCRIPTOR
    {
        public uint Attributes;
        public uint Name;
        public uint ModuleHandle;
        public uint DelayImportAddressTable;
        public uint DelayImportNameTable;
        public uint BoundDelayImportTable;
        public uint UnloadDelayImportTable;
        public uint TimeDateStamp;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY64
    {
        public ulong StartAddressOfRawData;
        public ulong EndAddressOfRawData;
        public ulong AddressOfIndex;
        public ulong AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;     // RVA from base of image
        public uint AddressOfNames;         // RVA from base of image
        public uint AddressOfNameOrdinals;  // RVA from base of image
    }

    // COM descriptor (managed assemblies). Included for completeness.
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_COR20_HEADER
    {
        public uint cb;
        public ushort MajorRuntimeVersion;
        public ushort MinorRuntimeVersion;
        public IMAGE_DATA_DIRECTORY MetaData;
        public uint Flags;
        public uint EntryPointToken;
        public IMAGE_DATA_DIRECTORY Resources;
        public IMAGE_DATA_DIRECTORY StrongNameSignature;
        public IMAGE_DATA_DIRECTORY CodeManagerTable;
        public IMAGE_DATA_DIRECTORY VTableFixups;
        public IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
        public IMAGE_DATA_DIRECTORY ManagedNativeHeader;
    }

    #endregion

    // ---------------------------------------------------------------------
    // Core PE headers
    // ---------------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
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
        public int e_lfanew;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public MagicType Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
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
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        [FieldOffset(0)]
        public uint Characteristics;
        [FieldOffset(0)]
        public uint OriginalFirstThunk;
        [FieldOffset(4)]
        public uint TimeDateStamp;
        [FieldOffset(8)]
        public uint ForwarderChain;
        [FieldOffset(12)]
        public uint Name;
        [FieldOffset(16)]
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_THUNK_DATA64
    {
        [FieldOffset(0)]
        public ulong ForwarderString;
        [FieldOffset(0)]
        public ulong Function;
        [FieldOffset(0)]
        public ulong Ordinal;
        [FieldOffset(0)]
        public ulong AddressOfData;
    }
} 