using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ManualImageMapper;

/// <summary>
/// Thin, demo-oriented manual mapper that uses FFI helpers. Not battle-tested, but shows all moving pieces.
/// </summary>
public static class ManualMapper
{
    /// <summary>
    /// Performs a complete manual map of <paramref name="dllBytes"/> into <paramref name="pid"/> and executes DllMain via thread-hijack.
    /// </summary>
    public static void Inject(byte[] dllBytes, int pid)
    {
        // Parse PE
        var nt = FFI.GetNtHeaders(dllBytes);
        var sections = FFI.GetSectionHeaders(dllBytes);

        // 1. Open target
        var hProcess = FFI.OpenTargetProcess(pid);
        try
        {
            // 2. Allocate memory for entire image (headers + sections) RW
            var remoteBase = FFI.AllocateMemory(hProcess, nt.OptionalHeader.SizeOfImage);

            // 3. Copy headers
            FFI.WriteMemory(hProcess, remoteBase, dllBytes.AsSpan(0, (int)nt.OptionalHeader.SizeOfHeaders).ToArray());

            // 4. Map and protect sections
            FFI.MapSections(hProcess, remoteBase, dllBytes, sections);

            // 5. Perform relocations
            ApplyRelocations(hProcess, remoteBase, dllBytes, nt);

            // 6. Resolve imports (best-effort using local addresses)
            ResolveImports(hProcess, remoteBase, dllBytes, nt);

            // 7. TLS callbacks
            RunTlsCallbacks(hProcess, remoteBase, dllBytes, nt);

            // 8. Finalise – flush cache, erase headers
            FFI.FlushInstructionCache(hProcess, remoteBase, nt.OptionalHeader.SizeOfImage);
            EraseHeaders(hProcess, remoteBase, nt.OptionalHeader.SizeOfHeaders);

            // 9. Execute entrypoint via thread hijacking (restores original RIP with tiny stub)
            HijackFirstThread(pid, hProcess, remoteBase, nt);

            // 10. Unlink from PEB lists for stealth
            UnlinkFromPEB(hProcess, remoteBase);
        }
        finally
        {
            FFI.CloseHandleSafe(hProcess);
        }
    }

    // ------------------------------------------------------------------
    // Relocations
    // ------------------------------------------------------------------

    private static void ApplyRelocations(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, FFI.IMAGE_NT_HEADERS64 nt)
    {
        var relocDir = nt.OptionalHeader.DataDirectory[(int)FFI.ImageDirectoryEntry.BASERELOC];
        if (relocDir.Size == 0) return;

        var delta = (long)(remoteBase.ToInt64() - (long)nt.OptionalHeader.ImageBase);
        int processed = 0;
        while (processed < relocDir.Size)
        {
            var reloc = FFI.BytesToStructure<FFI.IMAGE_BASE_RELOCATION>(localImage.ToArray(), (int)relocDir.VirtualAddress + processed);
            processed += Marshal.SizeOf<FFI.IMAGE_BASE_RELOCATION>();

            int entryCount = ((int)reloc.SizeOfBlock - Marshal.SizeOf<FFI.IMAGE_BASE_RELOCATION>()) / 2;
            for (int i = 0; i < entryCount; i++)
            {
                ushort entry = BitConverter.ToUInt16(localImage.Slice((int)relocDir.VirtualAddress + processed + i * 2, 2));
                int type = entry >> 12;
                int offset = entry & 0xFFF;

                if (type == FFI.IMAGE_REL_BASED_DIR64)
                {
                    var patchAddrRemote = remoteBase + (int)reloc.VirtualAddress + offset;
                    var origBytes = FFI.ReadMemory(hProcess, patchAddrRemote, 8);
                    ulong origPtr = BitConverter.ToUInt64(origBytes);
                    ulong newPtr = (ulong)(origPtr + (ulong)delta);
                    FFI.WriteMemory(hProcess, patchAddrRemote, BitConverter.GetBytes(newPtr));
                }
            }
            processed += (entryCount * 2);
        }
    }

    // ------------------------------------------------------------------
    // Import resolution (simple)
    // ------------------------------------------------------------------

    private static void ResolveImports(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, FFI.IMAGE_NT_HEADERS64 nt)
    {
        var importDir = nt.OptionalHeader.DataDirectory[(int)FFI.ImageDirectoryEntry.IMPORT];
        if (importDir.Size == 0) return;

        int descriptorSize = Marshal.SizeOf<FFI.IMAGE_IMPORT_DESCRIPTOR>();
        int index = 0;
        while (true)
        {
            var desc = FFI.BytesToStructure<FFI.IMAGE_IMPORT_DESCRIPTOR>(localImage.ToArray(), (int)importDir.VirtualAddress + index * descriptorSize);
            if (desc.Name == 0) break;

            string dllName = ReadAnsiString(localImage, desc.Name);

            // ensure module loaded in remote – load if missing
            var hModuleRemote = FFI.GetModuleHandle(dllName);
            if (hModuleRemote == nint.Zero)
            {
                // allocate ascii string in remote, call LoadLibraryA
                var bytes = System.Text.Encoding.ASCII.GetBytes(dllName + "\0");
                var strAddr = FFI.AllocateMemory(hProcess, (uint)bytes.Length, FFI.PAGE_READWRITE);
                FFI.WriteMemory(hProcess, strAddr, bytes);

                var loadLib = FFI.GetProcAddress(FFI.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                FFI.CreateRemoteThreadAndWait(hProcess, loadLib, strAddr);
                FFI.FreeMemory(hProcess, strAddr);
            }

            // Now fill IAT
            int thunkIdx = 0;
            while (true)
            {
                ulong importRef = BitConverter.ToUInt64(localImage.Slice((int)desc.OriginalFirstThunk + thunkIdx * 8, 8));
                if (importRef == 0) break;

                nint funcPtr;
                if ((importRef & 0x8000000000000000) != 0) // ordinal
                {
                    ushort ordinal = (ushort)(importRef & 0xFFFF);
                    funcPtr = FFI.GetProcAddress(FFI.GetModuleHandle(dllName), (nint)ordinal);
                }
                else
                {
                    uint nameRva = (uint)(importRef & 0x7FFFFFFF_FFFFFFFF);
                    string funcName = ReadAnsiString(localImage, nameRva + 2); // skip hint
                    funcPtr = FFI.GetProcAddress(FFI.GetModuleHandle(dllName), funcName);
                }

                var iatEntryRemote = remoteBase + (int)desc.FirstThunk + thunkIdx * sizeof(ulong);
                FFI.WriteMemory(hProcess, iatEntryRemote, BitConverter.GetBytes((ulong)funcPtr));
                thunkIdx++;
            }
            index++;
        }
    }

    private static unsafe string ReadAnsiString(ReadOnlySpan<byte> image, uint rva)
    {
        int offset = (int)rva;
        int len = 0;
        while (image[offset + len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(image.Slice(offset, len));
    }

    // ------------------------------------------------------------------
    // Header erase
    // ------------------------------------------------------------------

    private static void EraseHeaders(nint hProcess, nint remoteBase, uint headerSize)
    {
        var zeros = new byte[headerSize];
        FFI.ProtectMemory(hProcess, remoteBase, headerSize, FFI.PAGE_READWRITE);
        FFI.WriteMemory(hProcess, remoteBase, zeros);
    }

    // ------------------------------------------------------------------
    // Thread hijack (simple – picks first thread of target)
    // ------------------------------------------------------------------

    private static void HijackFirstThread(int pid, nint hProcess, nint moduleBase, FFI.IMAGE_NT_HEADERS64 nt)
    {
        var snap = FFI.CreateToolhelp32Snapshot(FFI.TH32CS_SNAPTHREAD, 0);
        if (snap == nint.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        try
        {
            FFI.THREADENTRY32 entry = new()
            {
                dwSize = (uint)Marshal.SizeOf<FFI.THREADENTRY32>()
            };
            if (!FFI.Thread32First(snap, ref entry)) return;
            do
            {
                if (entry.th32OwnerProcessID != (uint)pid) continue;
                var hThread = FFI.OpenThread(FFI.THREAD_ALL_ACCESS, false, entry.th32ThreadID);
                if (hThread == nint.Zero) continue;

                try
                {
                    FFI.SuspendThread(hThread);
                    var ctx = new FFI.CONTEXT64 { ContextFlags = FFI.CONTEXT_FULL };
                    FFI.GetThreadContext(hThread, ref ctx);

                    nint stubAddr = BuildAndWriteLoaderStub(hProcess, moduleBase, nt, (nint)ctx.Rip);
                    ctx.Rip = (ulong)stubAddr;
                    FFI.SetThreadContext(hThread, ref ctx);
                    FFI.ResumeThread(hThread);
                    break; // hijacked one thread, good enough
                }
                finally
                {
                    FFI.CloseHandleSafe(hThread);
                }
            } while (FFI.Thread32Next(snap, ref entry));
        }
        finally
        {
            FFI.CloseHandleSafe(snap);
        }
    }

    // ------------------------------------------------------------------
    // Loader stub: DllMain + RIP restore (TLS already handled separately)
    // ------------------------------------------------------------------
    private static nint BuildAndWriteLoaderStub(nint hProcess, nint moduleBase, FFI.IMAGE_NT_HEADERS64 nt, nint originalRip)
    {
        var dllMain = moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint;

        byte[] stub = BuildStubBytes((ulong)moduleBase, (ulong)dllMain, (ulong)originalRip);

        var remote = FFI.AllocateMemory(hProcess, (uint)stub.Length, FFI.PAGE_EXECUTE_READWRITE);
        FFI.WriteMemory(hProcess, remote, stub);
        FFI.ProtectMemory(hProcess, remote, (uint)stub.Length, FFI.PAGE_EXECUTE_READ);
        return remote;
    }

    private static byte[] BuildStubBytes(ulong moduleBase, ulong dllMain, ulong originalRip)
    {
        List<byte> b = new();

        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            if (reg < 8)
                Emit(0x48, (byte)(0xB8 + reg));
            else
                Emit(0x49, (byte)(0xB8 + (reg - 8)));
            Emit(BitConverter.GetBytes(imm));
        }

        // RCX = moduleBase
        MovRegImm64(1, moduleBase);
        // EDX = 1 (DLL_PROCESS_ATTACH)
        Emit(0xBA, 0x01, 0x00, 0x00, 0x00);
        // XOR R8D,R8D (reserved arg = NULL)
        Emit(0x41, 0x31, 0xC0);
        // RAX = dllMain
        MovRegImm64(0, dllMain);
        // CALL RAX
        Emit(0xFF, 0xD0);
        // RAX = originalRip
        MovRegImm64(0, originalRip);
        // JMP RAX
        Emit(0xFF, 0xE0);

        return b.ToArray();
    }

    // ------------------------------------------------------------------
    // PEB unlink
    // ------------------------------------------------------------------
    private static void UnlinkFromPEB(nint hProcess, nint moduleBase)
    {
        // Query PEB
        var status = FFI.NtQueryInformationProcess(hProcess, FFI.PROCESSINFOCLASS.ProcessBasicInformation, out var pbi, Marshal.SizeOf<FFI.PROCESS_BASIC_INFORMATION>(), out _);
        if (status != 0) return;
        nint peb = pbi.PebBaseAddress;
        // Offsets for x64 (could vary by build, but stable for Win10/11)
        const int offsetLdr = 0x18;
        const int offsetInLoadOrder = 0x10;
        const int entryOffsetDllBase = 0x30;
        const int entryOffsetInLoad = 0x00;
        const int entryOffsetInMem = 0x10;
        const int entryOffsetInInit = 0x20;

        byte[] buf8 = new byte[8];
        // Read Ldr
        FFI.ReadProcessMemory(hProcess, peb + offsetLdr, buf8, 8, out _);
        nint ldr = (nint)BitConverter.ToInt64(buf8);
        // Read list head
        FFI.ReadProcessMemory(hProcess, ldr + offsetInLoadOrder, buf8, 8, out _);
        nint listHead = (nint)BitConverter.ToInt64(buf8);
        nint current = listHead;
        int safety = 0;
        while (safety++ < 256)
        {
            // Read dll base
            byte[] dllBuf = new byte[8];
            FFI.ReadProcessMemory(hProcess, current + entryOffsetDllBase, dllBuf, 8, out _);
            nint dllBaseRead = (nint)BitConverter.ToInt64(dllBuf);
            if (dllBaseRead == moduleBase)
            {
                // Unlink in all three lists
                void Unlink(int offset)
                {
                    byte[] flinkBuf = new byte[8];
                    byte[] blinkBuf = new byte[8];
                    FFI.ReadProcessMemory(hProcess, current + offset, flinkBuf, 8, out _);
                    FFI.ReadProcessMemory(hProcess, current + offset + 8, blinkBuf, 8, out _);
                    nint flink = (nint)BitConverter.ToInt64(flinkBuf);
                    nint blink = (nint)BitConverter.ToInt64(blinkBuf);
                    // blink->Flink = flink
                    FFI.WriteMemory(hProcess, blink, BitConverter.GetBytes((ulong)flink));
                    // flink->Blink = blink
                    FFI.WriteMemory(hProcess, flink + 8, BitConverter.GetBytes((ulong)blink));
                }
                Unlink(entryOffsetInLoad);
                Unlink(entryOffsetInMem);
                Unlink(entryOffsetInInit);
                break;
            }
            // Next entry
            FFI.ReadProcessMemory(hProcess, current, buf8, 8, out _);
            current = (nint)BitConverter.ToInt64(buf8);
            if (current == listHead || current == nint.Zero) break;
        }
    }

    // ------------------------------------------------------------------
    // TLS callbacks
    // ------------------------------------------------------------------

    private static void RunTlsCallbacks(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, FFI.IMAGE_NT_HEADERS64 nt)
    {
        var tlsDirEntry = nt.OptionalHeader.DataDirectory[(int)FFI.ImageDirectoryEntry.TLS];
        if (tlsDirEntry.Size == 0) return;

        var tls = FFI.BytesToStructure<FFI.IMAGE_TLS_DIRECTORY64>(localImage.ToArray(), (int)tlsDirEntry.VirtualAddress);
        if (tls.AddressOfCallBacks == 0) return;

        ulong delta = (ulong)(remoteBase.ToInt64() - (long)nt.OptionalHeader.ImageBase);
        ulong callbacksVA = tls.AddressOfCallBacks + delta; // adjusted to remote base

        int index = 0;
        while (true)
        {
            var callbackAddrBytes = FFI.ReadMemory(hProcess, (nint)(callbacksVA + (ulong)(index * sizeof(ulong))), sizeof(ulong));
            ulong cb = BitConverter.ToUInt64(callbackAddrBytes);
            if (cb == 0) break;

            // Invoke callback with DllHandle parameter (remoteBase). Reason & reserved will be garbage, but many callbacks ignore them.
            FFI.CreateRemoteThreadAndWait(hProcess, (nint)cb, remoteBase, true);
            index++;
        }
    }
}