using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Serilog;

namespace ManualImageMapper;

/// <summary>
/// Represents different injection modes with their associated configuration.
/// </summary>
public abstract record InjectionMode
{
    public sealed record ThreadHijacking(bool EnableDebugPrivilege = true) : InjectionMode;
    public sealed record CreateRemoteThread(uint TimeoutMs = 30_000) : InjectionMode;
}

/// <summary>
/// Thin, demo-oriented manual mapper that uses FFI helpers. Not battle-tested, but shows all moving pieces.
/// </summary>
public static class ManualMapper
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(ManualMapper));

    /// <summary>
    /// Performs a complete manual map of <paramref name="dllBytes"/> into <paramref name="pid"/> and executes DllMain.
    /// </summary>
    /// <param name="mode">The injection mode and its configuration</param>
    public static void Inject(byte[] dllBytes, int pid, InjectionMode mode)
    {
        // Parse PE
        var nt = FFI.GetNtHeaders(dllBytes);
        var sections = FFI.GetSectionHeaders(dllBytes);

        Log.Information("Opening target process {Pid}", pid);
        // 1. Open target
        var hProcess = FFI.OpenTargetProcess(pid);
        try
        {
            Log.Debug("Allocating {Size} bytes in target", nt.OptionalHeader.SizeOfImage);
            // 2. Allocate memory for entire image (headers + sections) RW
            var remoteBase = FFI.AllocateMemory(hProcess, nt.OptionalHeader.SizeOfImage);

            Log.Debug("Copying headers ({HeaderSize} bytes)", nt.OptionalHeader.SizeOfHeaders);
            // 3. Copy headers
            FFI.WriteMemory(hProcess, remoteBase, dllBytes.AsSpan(0, (int)nt.OptionalHeader.SizeOfHeaders).ToArray());

            Log.Debug("Mapping {SectionCount} sections", sections.Count);
            // 4. Map sections – keep them RW for now
            FFI.MapSections(hProcess, remoteBase, dllBytes, sections);

            Log.Debug("Applying relocations");
            // 5. Perform relocations
            ApplyRelocations(hProcess, remoteBase, dllBytes, nt, sections);

            Log.Debug("Resolving imports");
            // 6. Resolve imports (best-effort using local addresses)
            ResolveImports(hProcess, remoteBase, dllBytes, nt, sections);

            Log.Debug("Setting final section protections");
            // 7. Apply final section protections now that patching is done
            FFI.SetSectionProtections(hProcess, remoteBase, sections);

            Log.Debug("Flushing instruction cache & erasing headers");
            // 8. Finalise – flush cache, erase headers (TLS callbacks handled via stub)
            FFI.FlushInstructionCache(hProcess, remoteBase, nt.OptionalHeader.SizeOfImage);
            EraseHeaders(hProcess, remoteBase, nt.OptionalHeader.SizeOfHeaders);

            // 9. Execute DllMain based on injection mode
            switch (mode)
            {
                case InjectionMode.ThreadHijacking hijack:
                    Log.Information("Hijacking thread to execute DllMain (debug privilege: {EnableDebug})", hijack.EnableDebugPrivilege);
                    HijackFirstThread(pid, hProcess, remoteBase, nt, hijack.EnableDebugPrivilege);
                    break;

                case InjectionMode.CreateRemoteThread remoteThread:
                    Log.Information("Using CreateRemoteThread to execute DllMain (timeout: {TimeoutMs}ms)", remoteThread.TimeoutMs);
                    var dllMain = remoteBase + (int)nt.OptionalHeader.AddressOfEntryPoint;
                    Log.Debug("DllMain at 0x{DllMain:X}", (ulong)dllMain);

                    var wrapperStub = CreateDllMainWrapper(hProcess, (ulong)dllMain, (ulong)remoteBase);
                    Log.Debug("Wrapper stub at 0x{Wrapper:X}", (ulong)wrapperStub);

                    var hThread = FFI.CreateRemoteThreadAndWait(hProcess, wrapperStub, nint.Zero, wait: false);
                    Log.Debug("Created thread 0x{Thread:X} for wrapper", (ulong)hThread);
                    if (hThread != nint.Zero)
                    {
                        FFI.WaitForSingleObject(hThread, remoteThread.TimeoutMs);
                        FFI.CloseHandleSafe(hThread);
                    }
                    break;

                default:
                    throw new ArgumentException($"Unsupported injection mode: {mode.GetType().Name}");
            }

            Log.Debug("Unlinking module from PEB");
            // 10. Unlink from PEB lists for stealth
            UnlinkFromPEB(hProcess, remoteBase);
        }
        finally
        {
            Log.Information("Finished injecting – closing handle");
            FFI.CloseHandleSafe(hProcess);
        }
    }

    /// <summary>
    /// Applies the relocation table to patch absolute addresses in the remote image.
    /// </summary>
    private static void ApplyRelocations(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, FFI.IMAGE_NT_HEADERS64 nt, IReadOnlyList<FFI.IMAGE_SECTION_HEADER> sections)
    {
        var relocDir = nt.OptionalHeader.DataDirectory[(int)FFI.ImageDirectoryEntry.BASERELOC];
        if (relocDir.Size == 0) return;

        var delta = remoteBase.ToInt64() - (long)nt.OptionalHeader.ImageBase;

        var localArr = localImage.ToArray();
        Log.Debug("Relocation directory size {Size} at RVA 0x{Rva:X}", relocDir.Size, relocDir.VirtualAddress);
        int processed = 0;
        int relocBaseOffset = RvaToOffset(relocDir.VirtualAddress, sections);

        while (processed < relocDir.Size)
        {
            int blockOffset = relocBaseOffset + processed;
            var reloc = FFI.BytesToStructure<FFI.IMAGE_BASE_RELOCATION>(localArr, blockOffset);
            processed += Marshal.SizeOf<FFI.IMAGE_BASE_RELOCATION>();

            int entryCount = ((int)reloc.SizeOfBlock - Marshal.SizeOf<FFI.IMAGE_BASE_RELOCATION>()) / 2;
            Log.Debug("Reloc block VA 0x{BlockVa:X} entries {Count}", reloc.VirtualAddress, entryCount);
            for (int i = 0; i < entryCount; i++)
            {
                ushort entryVal = BitConverter.ToUInt16(localArr, relocBaseOffset + processed + i * 2);
                int type = entryVal >> 12;
                int offset = entryVal & 0xFFF;

                if (type == FFI.IMAGE_REL_BASED_DIR64)
                {
                    var patchAddrRemote = remoteBase + (int)reloc.VirtualAddress + offset;
                    var origBytes = FFI.ReadMemory(hProcess, patchAddrRemote, 8);
                    ulong origPtr = BitConverter.ToUInt64(origBytes);
                    ulong newPtr = origPtr + (ulong)delta;
                    FFI.WriteMemory(hProcess, patchAddrRemote, BitConverter.GetBytes(newPtr));
                    Log.Verbose("Patched 0x{PatchAddr:X}: {OrigPtr:X} -> {NewPtr:X}", (ulong)patchAddrRemote, origPtr, newPtr);
                }
            }
            processed += entryCount * 2;
        }
    }

    /// <summary>
    /// Resolves DLL imports by writing the appropriate function pointers into the remote IAT.
    /// </summary>
    private static void ResolveImports(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, FFI.IMAGE_NT_HEADERS64 nt, IReadOnlyList<FFI.IMAGE_SECTION_HEADER> sections)
    {
        var importDir = nt.OptionalHeader.DataDirectory[(int)FFI.ImageDirectoryEntry.IMPORT];
        if (importDir.Size == 0) return;

        int descriptorSize = Marshal.SizeOf<FFI.IMAGE_IMPORT_DESCRIPTOR>();
        int index = 0;
        var localArr = localImage.ToArray();
        Log.Debug("Processing import directory (size {Size}) at RVA 0x{Rva:X}", importDir.Size, importDir.VirtualAddress);
        while (true)
        {
            int descOffset = RvaToOffset(importDir.VirtualAddress + (uint)(index * descriptorSize), sections);
            var desc = FFI.BytesToStructure<FFI.IMAGE_IMPORT_DESCRIPTOR>(localArr, descOffset);
            if (desc.Name == 0) break;

            string dllName = ReadAnsiString(localArr, desc.Name, sections);
            Log.Debug("Import descriptor {Dll}", dllName);

            // ensure module loaded in remote – load if missing
            var hModuleRemote = FFI.GetModuleHandle(dllName);
            if (hModuleRemote == nint.Zero)
            {
                Log.Debug("{Dll} not loaded – calling LoadLibraryA", dllName);
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
                uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
                int thunkOffset = RvaToOffset(thunkRva + (uint)(thunkIdx * 8), sections);
                ulong importRef = BitConverter.ToUInt64(localArr, thunkOffset);
                if (importRef == 0) break;

                nint funcPtr;
                string identifier;
                if ((importRef & 0x8000000000000000) != 0) // ordinal
                {
                    ushort ordinal = (ushort)(importRef & 0xFFFF);
                    funcPtr = FFI.GetProcAddress(FFI.GetModuleHandle(dllName), ordinal);
                    identifier = "ordinal #" + ordinal;
                }
                else
                {
                    uint nameRva = (uint)(importRef & 0x7FFFFFFF_FFFFFFFF);
                    string funcName = ReadAnsiString(localArr, nameRva + 2, sections); // skip hint
                    funcPtr = FFI.GetProcAddress(FFI.GetModuleHandle(dllName), funcName);
                    identifier = funcName;
                }

                var iatEntryRemote = remoteBase + (int)desc.FirstThunk + thunkIdx * sizeof(ulong);
                FFI.WriteMemory(hProcess, iatEntryRemote, BitConverter.GetBytes((ulong)funcPtr));
                Log.Verbose("Resolved {Dll}!{Ident} -> 0x{Ptr:X}", dllName, identifier, (ulong)funcPtr);
                thunkIdx++;
            }
            index++;
        }
    }

    /// <summary>
    /// Reads a null-terminated ANSI string from the local PE image given an RVA.
    /// </summary>
    private static string ReadAnsiString(byte[] image, uint rva, IReadOnlyList<FFI.IMAGE_SECTION_HEADER> sections)
    {
        int offset = RvaToOffset(rva, sections);
        int len = 0;
        while (image[offset + len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(image.AsSpan(offset, len));
    }

    /// <summary>
    /// Converts a Relative Virtual Address (RVA) to a file offset using the provided section headers.
    /// </summary>
    private static int RvaToOffset(uint rva, IReadOnlyList<FFI.IMAGE_SECTION_HEADER> sections)
    {
        foreach (var section in sections)
        {
            var start = section.VirtualAddress;
            var end = start + Math.Max(section.SizeOfRawData, section.VirtualSize);
            if (rva >= start && rva < end)
            {
                return (int)(rva - start + section.PointerToRawData);
            }
        }
        // If RVA falls into headers, return as-is
        return (int)rva;
    }

    /// <summary>
    /// Zeroes the PE headers in the remote image for basic stealth.
    /// </summary>
    private static void EraseHeaders(nint hProcess, nint remoteBase, uint headerSize)
    {
        var zeros = new byte[headerSize];
        FFI.ProtectMemory(hProcess, remoteBase, headerSize, FFI.PAGE_READWRITE);
        FFI.WriteMemory(hProcess, remoteBase, zeros);
    }

    /// <summary>
    /// Suspends the first thread of the target process and hijacks its RIP to execute our loader stub.
    /// </summary>
    private static void HijackFirstThread(int pid, nint hProcess, nint moduleBase, FFI.IMAGE_NT_HEADERS64 nt, bool enableDebugPrivilege)
    {
        // Try to enable SeDebugPrivilege for better thread access
        if (enableDebugPrivilege)
        {
            FFI.EnableSeDebugPrivilege();
        }

        var snap = FFI.CreateToolhelp32Snapshot(FFI.TH32CS_SNAPTHREAD, 0);
        if (snap == nint.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        try
        {
            FFI.THREADENTRY32 entry = new()
            {
                dwSize = (uint)Marshal.SizeOf<FFI.THREADENTRY32>()
            };
            if (!FFI.Thread32First(snap, ref entry)) return;
            bool hijacked = false;
            do
            {
                if (entry.th32OwnerProcessID != (uint)pid) continue;
                var hThread = FFI.OpenThread(FFI.THREAD_ALL_ACCESS, false, entry.th32ThreadID);
                if (hThread == nint.Zero) continue;

                try
                {
                    FFI.SuspendThread(hThread);
                    var ctx = new FFI.CONTEXT64 { ContextFlags = FFI.CONTEXT_ALL };
                    if (!FFI.GetThreadContext(hThread, ref ctx))
                    {
                        Log.Warning("GetThreadContext failed for TID {Tid} (err {Err})", entry.th32ThreadID, Marshal.GetLastWin32Error());
                        FFI.ResumeThread(hThread);
                        continue;
                    }
                    if (ctx.Rip == 0)
                    {
                        Log.Warning("Thread {Tid} has RIP=0 – skipping", entry.th32ThreadID);
                        FFI.ResumeThread(hThread);
                        continue;
                    }

                    nint stubAddr = BuildAndWriteLoaderStub(hProcess, moduleBase, nt, (nint)ctx.Rip);
                    Log.Debug("Thread {Tid}: original RIP 0x{Rip:X} -> stub 0x{Stub:X}", entry.th32ThreadID, ctx.Rip, (ulong)stubAddr);
                    ctx.Rip = (ulong)stubAddr;
                    FFI.SetThreadContext(hThread, ref ctx);
                    FFI.ResumeThread(hThread);
                    Log.Debug("Resumed thread {Tid}", entry.th32ThreadID);
                    hijacked = true;
                    break; // hijacked one thread, good enough
                }
                finally
                {
                    FFI.CloseHandleSafe(hThread);
                }
            } while (FFI.Thread32Next(snap, ref entry));

            if (!hijacked)
            {
                Log.Warning("Failed to hijack any thread – falling back to CreateRemoteThread");
                var dllMain = moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint;
                var wrapperStub = CreateDllMainWrapper(hProcess, (ulong)dllMain, (ulong)moduleBase);
                FFI.CreateRemoteThreadAndWait(hProcess, wrapperStub, nint.Zero, wait: false);
            }
        }
        finally
        {
            FFI.CloseHandleSafe(snap);
        }
    }

    /// <summary>
    /// Builds a small shell-code stub that calls TLS callbacks (if any), invokes DllMain, and then returns execution to the original RIP.
    /// </summary>
    private static nint BuildAndWriteLoaderStub(nint hProcess, nint moduleBase, FFI.IMAGE_NT_HEADERS64 nt, nint originalRip)
    {
        var dllMain = moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint;

        // Build TLS callback array (if any) from remote memory to avoid CreateRemoteThread
        var tlsDir = nt.OptionalHeader.DataDirectory[(int)FFI.ImageDirectoryEntry.TLS];
        List<ulong> callbacks = [];
        if (tlsDir.Size != 0)
        {
            var tlsRemote = FFI.ReadMemory(hProcess, moduleBase + (int)tlsDir.VirtualAddress, Marshal.SizeOf<FFI.IMAGE_TLS_DIRECTORY64>());
            var tlsStruct = FFI.BytesToStructure<FFI.IMAGE_TLS_DIRECTORY64>(tlsRemote, 0);
            if (tlsStruct.AddressOfCallBacks != 0)
            {
                Log.Debug("Collecting TLS callbacks");
                ulong cbPtr = tlsStruct.AddressOfCallBacks;
                while (true)
                {
                    var buf = FFI.ReadMemory(hProcess, (nint)cbPtr, 8);
                    ulong cb = BitConverter.ToUInt64(buf);
                    if (cb == 0) break;
                    callbacks.Add(cb);
                    cbPtr += 8;
                }
            }
        }
        Log.Debug("Total TLS callbacks: {Count}", callbacks.Count);

        // allocate remote array
        var arrBytes = new List<byte>();
        foreach (var c in callbacks) arrBytes.AddRange(BitConverter.GetBytes(c));
        arrBytes.AddRange(BitConverter.GetBytes((ulong)0));
        var callbacksRemote = FFI.AllocateMemory(hProcess, (uint)arrBytes.Count, FFI.PAGE_READWRITE);
        FFI.WriteMemory(hProcess, callbacksRemote, arrBytes.ToArray());

        byte[] stub = BuildStubBytes((ulong)moduleBase, (ulong)dllMain, (ulong)callbacksRemote, (ulong)originalRip);
        Log.Debug("Loader stub size {Size} bytes", stub.Length);

        var remote = FFI.AllocateMemory(hProcess, (uint)stub.Length, FFI.PAGE_EXECUTE_READWRITE);
        FFI.WriteMemory(hProcess, remote, stub);
        FFI.ProtectMemory(hProcess, remote, (uint)stub.Length, FFI.PAGE_EXECUTE_READ);
        // Ensure CPU sees fresh instructions
        FFI.FlushInstructionCache(hProcess, remote, (uint)stub.Length);
        return remote;
    }

        private static byte[] BuildStubBytes(ulong moduleBase, ulong dllMain, ulong callbacksAddr, ulong originalRip)
    {
        List<byte> b = [];

        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            if (reg < 8)
                Emit(0x48, (byte)(0xB8 + reg));
            else
                Emit(0x49, (byte)(0xB8 + (reg - 8)));
            Emit(BitConverter.GetBytes(imm));
        }

        // Save volatile regs we clobber FIRST (before any stack operations)
        Emit(0x50); // push rax
        Emit(0x51); // push rcx
        Emit(0x52); // push rdx
        Emit(0x41, 0x50); // push r8
        Emit(0x53); // push rbx (we'll use it for TLS)

        // Align stack to 16-byte boundary and allocate shadow space
        // We've pushed 5 registers (40 bytes), so RSP is 16-byte aligned
        Emit(0x48, 0x83, 0xEC, 0x20); // sub rsp, 32 (shadow space)

        // If callbacks array != 0, call TLS callbacks first
        if (callbacksAddr != 0)
        {
            // RBX = callbacksAddr
            MovRegImm64(3, callbacksAddr);
            int loopLabel = b.Count;
            // RAX = [RBX] (get callback address)
            Emit(0x48, 0x8B, 0x03);
            // TEST RAX,RAX (check if null)
            Emit(0x48, 0x85, 0xC0);
            // JZ -> afterCallbacks
            Emit(0x74, 0x00); int jePos = b.Count - 1;

            // Call TLS callback with proper parameters:
            // RCX = moduleBase (hModule)
            MovRegImm64(1, moduleBase);
            // RDX = DLL_PROCESS_ATTACH (1)
            Emit(0xBA, 0x01, 0x00, 0x00, 0x00);
            // R8 = NULL (lpvReserved)
            Emit(0x41, 0x31, 0xC0); // xor r8d,r8d
            // Call the TLS callback
            Emit(0xFF, 0xD0); // call rax
            
            // Move to next callback
            Emit(0x48, 0x83, 0xC3, 0x08); // add rbx,8
            Emit(0xEB, (byte)(loopLabel - (b.Count + 1))); // jmp loop

            // patch JZ offset
            b[jePos] = (byte)(b.Count - (jePos + 1));
        }

        // Now call DllMain with proper x64 calling convention
        // RCX = hInstance (moduleBase)
        MovRegImm64(1, moduleBase);
        // RDX = fdwReason (DLL_PROCESS_ATTACH = 1)
        Emit(0xBA, 0x01, 0x00, 0x00, 0x00);
        // R8 = lpvReserved (NULL)
        Emit(0x41, 0x31, 0xC0); // xor r8d, r8d
        
        // Call DllMain
        MovRegImm64(0, dllMain); // RAX = dllMain
        Emit(0xFF, 0xD0); // call rax

        // Restore stack (remove shadow space)
        Emit(0x48, 0x83, 0xC4, 0x20); // add rsp, 32

        // Restore registers in reverse order
        Emit(0x5B); // pop rbx
        Emit(0x41, 0x58); // pop r8
        Emit(0x5A); // pop rdx
        Emit(0x59); // pop rcx
        Emit(0x58); // pop rax

        if (originalRip == 0)
        {
            // RET
            Emit(0xC3);
        }
        else
        {
            // JMP originalRip to continue normal execution
            MovRegImm64(0, originalRip); // RAX = originalRip
            Emit(0xFF, 0xE0); // jmp rax
        }

        return b.ToArray();
    }

    /// <summary>
    /// Unlinks the mapped module from the PEB lists to make it less visible to module inspections.
    /// </summary>
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

    /// <summary>
    /// Creates a small stub that calls DllMain with proper parameters: DllMain(hInstance, DLL_PROCESS_ATTACH, NULL)
    /// </summary>
    private static nint CreateDllMainWrapper(nint hProcess, ulong dllMain, ulong moduleBase)
    {
        List<byte> b = [];
        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            if (reg < 8)
                Emit(0x48, (byte)(0xB8 + reg));
            else
                Emit(0x49, (byte)(0xB8 + (reg - 8)));
            Emit(BitConverter.GetBytes(imm));
        }

        // Allocate shadow space (32 bytes) + align stack to 16-byte boundary
        Emit(0x48, 0x83, 0xEC, 0x28); // sub rsp, 40 (32 shadow + 8 for alignment)

        // Set up DllMain parameters
        // RCX = hInstance (moduleBase)
        MovRegImm64(1, moduleBase);
        // RDX = fdwReason (DLL_PROCESS_ATTACH = 1)
        Emit(0xBA, 0x01, 0x00, 0x00, 0x00);
        // R8 = lpvReserved (NULL)
        Emit(0x41, 0x31, 0xC0); // xor r8d, r8d

        // Call DllMain
        MovRegImm64(0, dllMain); // RAX = dllMain
        Emit(0xFF, 0xD0); // call rax

        // Restore stack
        Emit(0x48, 0x83, 0xC4, 0x28); // add rsp, 40

        // Return
        Emit(0xC3); // ret

        var stub = b.ToArray();
        var remote = FFI.AllocateMemory(hProcess, (uint)stub.Length, FFI.PAGE_EXECUTE_READWRITE);
        FFI.WriteMemory(hProcess, remote, stub);
        FFI.ProtectMemory(hProcess, remote, (uint)stub.Length, FFI.PAGE_EXECUTE_READ);
        FFI.FlushInstructionCache(hProcess, remote, (uint)stub.Length);
        return remote;
    }
}