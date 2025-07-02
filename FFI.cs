using System.Runtime.InteropServices;
using System;
using System.Collections.Generic;

namespace ManualImageMapper;


public static partial class FFI
{
    #region Native Methods

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial nint GetProcAddress(nint hModule, string procName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint GetProcAddress(nint hModule, nint procName);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial nint GetModuleHandle(string lpModuleName);

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

    #endregion


    #region Higher Level Methods

    // ---------------------------------------------------------------------
    // Process / memory convenience wrappers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Opens the target process with minimal required permissions and returns the handle.
    /// Throws on failure.
    /// </summary>
    public static nint OpenTargetProcess(int pid)
    {
        const uint PROCESS_REQUIRED = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD;
        var handle = OpenProcess(PROCESS_REQUIRED, false, pid);
        if (handle == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess failed for PID {pid}");
        return handle;
    }

    /// <summary>
    /// Closes a process / object handle. Safe to call with IntPtr.Zero.
    /// </summary>
    public static void CloseHandleSafe(nint handle)
    {
        if (handle != nint.Zero)
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// Allocates memory in the remote process (MEM_COMMIT | MEM_RESERVE).
    /// </summary>
    public static nint AllocateMemory(nint hProcess, uint size, uint protection = PAGE_READWRITE)
    {
        var addr = VirtualAllocEx(hProcess, nint.Zero, size, MEM_COMMIT | MEM_RESERVE, protection);
        if (addr == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");
        return addr;
    }

    /// <summary>
    /// Frees previously allocated remote memory.
    /// </summary>
    public static void FreeMemory(nint hProcess, nint address)
    {
        if (address == nint.Zero) return;
        if (!VirtualFreeEx(hProcess, address, 0, MEM_RELEASE))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualFreeEx failed");
    }

    /// <summary>
    /// Writes a byte array to the specified remote address.
    /// </summary>
    public static void WriteMemory(nint hProcess, nint baseAddress, byte[] data)
    {
        if (!WriteProcessMemory(hProcess, baseAddress, data, (uint)data.Length, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
    }

    /// <summary>
    /// Reads <paramref name="size"/> bytes from the remote address.
    /// </summary>
    public static byte[] ReadMemory(nint hProcess, nint baseAddress, int size)
    {
        var buffer = new byte[size];
        if (!ReadProcessMemory(hProcess, baseAddress, buffer, size, out _))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");
        return buffer;
    }

    /// <summary>
    /// Changes the protection of a remote memory region.
    /// Returns the old protection value.
    /// </summary>
    public static uint ProtectMemory(nint hProcess, nint address, uint size, uint newProtect)
    {
        if (!VirtualProtectEx(hProcess, address, size, newProtect, out var oldProtect))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtectEx failed");
        return oldProtect;
    }

    /// <summary>
    /// Creates a remote thread and optionally waits for it to finish.
    /// Returns the thread handle.
    /// </summary>
    public static nint CreateRemoteThreadAndWait(nint hProcess, nint startAddress, nint parameter, bool wait = true)
    {
        var hThread = CreateRemoteThread(hProcess, nint.Zero, 0, startAddress, parameter, 0, nint.Zero);
        if (hThread == nint.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");

        if (wait)
        {
            WaitForSingleObject(hThread, INFINITE);
        }
        return hThread;
    }

    // ---------------------------------------------------------------------
    // PE parsing helpers (local – operates on the DLL image bytes)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Converts a raw byte buffer to a structure of type T.
    /// </summary>
    public static T BytesToStructure<T>(byte[] buffer, int offset = 0) where T : struct
    {
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var ptr = System.IntPtr.Add(handle.AddrOfPinnedObject(), offset);
            return Marshal.PtrToStructure<T>(ptr)!;
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Reads the DOS header from the in-memory image.
    /// </summary>
    public static IMAGE_DOS_HEADER GetDosHeader(byte[] image) => BytesToStructure<IMAGE_DOS_HEADER>(image, 0);

    /// <summary>
    /// Reads the NT headers from the in-memory image.
    /// </summary>
    public static IMAGE_NT_HEADERS64 GetNtHeaders(byte[] image)
    {
        var dos = GetDosHeader(image);
        return BytesToStructure<IMAGE_NT_HEADERS64>(image, dos.e_lfanew);
    }

    /// <summary>
    /// Returns all section headers for the PE image.
    /// </summary>
    public static List<IMAGE_SECTION_HEADER> GetSectionHeaders(byte[] image)
    {
        var dos = GetDosHeader(image);
        var nt = GetNtHeaders(image);
        int sectionOffset = dos.e_lfanew + Marshal.SizeOf<IMAGE_NT_HEADERS64>();
        int sectionSize = Marshal.SizeOf<IMAGE_SECTION_HEADER>();
        var list = new List<IMAGE_SECTION_HEADER>();
        for (int i = 0; i < nt.FileHeader.NumberOfSections; i++)
        {
            list.Add(BytesToStructure<IMAGE_SECTION_HEADER>(image, sectionOffset + i * sectionSize));
        }
        return list;
    }

    /// <summary>
    /// Aligns <paramref name="value"/> up to the next multiple of <paramref name="alignment"/>.
    /// </summary>
    public static uint AlignUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);

    // ---------------------------------------------------------------------
    // Section specific helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Maps section <see cref="SectionCharacteristics"/> flag combinations to PAGE_* protection flags.
    /// The mapping is simplified but sufficient for typical DLL sections.
    /// </summary>
    public static uint CharacteristicsToProtection(uint characteristics)
    {
        var exec = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) != 0;
        var read = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_READ) != 0;
        var write = (characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE) != 0;

        return (exec, read, write) switch
        {
            (false, false, false) => PAGE_NOACCESS,
            (false, true, false) => PAGE_READONLY,
            (false, true, true) => PAGE_READWRITE,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, true, true) => PAGE_EXECUTE_READWRITE,
            (true, false, false) => PAGE_EXECUTE,
            _ => PAGE_NOACCESS // fallback (rare)
        };
    }

    /// <summary>
    /// Writes each PE section into remote memory with initial RW permissions, then sets the final permissions based on the section characteristics.
    /// </summary>
    public static void MapSections(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        foreach (var section in sections)
        {
            // Determine local section slice
            var rawOffset = (int)section.PointerToRawData;
            var rawSize = (int)section.SizeOfRawData;
            var slice = localImage.Slice(rawOffset, rawSize);

            // Write to remote
            var remoteAddress = remoteBase + (int)section.VirtualAddress;
            WriteMemory(hProcess, remoteAddress, slice.ToArray()); // using Span, ToArray for convenience
        }

        // Second pass: set final protection
        foreach (var section in sections)
        {
            var size = AlignUp(section.VirtualSize, 0x1000); // page align
            var prot = CharacteristicsToProtection(section.Characteristics);
            var remoteAddress = remoteBase + (int)section.VirtualAddress;
            ProtectMemory(hProcess, remoteAddress, size, prot);
        }
    }

    #endregion
}


