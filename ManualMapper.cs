using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Serilog;

namespace ManualImageMapper;

/// <summary>
/// Different injection modes with their associated configuration.
/// </summary>
public abstract record InjectionMode
{
    public sealed record ThreadHijacking(TimeSpan DebugMarkerCheckDelay, bool EnableDebugPrivilege = true, bool EnableDebugMarker = false, bool LogGeneratedStub = false) : InjectionMode;
    public sealed record CreateRemoteThread(uint TimeoutMs = 30_000) : InjectionMode;
}

/// <summary>
/// Manual PE loader that injects DLLs into remote processes using thread hijacking or CreateRemoteThread.
/// </summary>
public static class ManualMapper
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(ManualMapper));

    /// <summary>
    /// Performs complete manual mapping of a DLL into a target process and executes DllMain.
    /// </summary>
    public static void Inject(byte[] dllBytes, int pid, InjectionMode mode)
    {
        var nt = FFI.GetNtHeaders(dllBytes);
        var sections = FFI.GetSectionHeaders(dllBytes);

        Log.Information("Opening target process {Pid}", pid);
        var hProcess = FFI.OpenTargetProcess(pid);
        try
        {
            Log.Debug("Allocating {Size} bytes in target", nt.OptionalHeader.SizeOfImage);
            var remoteBase = FFI.AllocateMemory(hProcess, nt.OptionalHeader.SizeOfImage);

            Log.Debug("Copying headers ({HeaderSize} bytes)", nt.OptionalHeader.SizeOfHeaders);
            FFI.WriteMemory(hProcess, remoteBase, dllBytes.AsSpan(0, (int)nt.OptionalHeader.SizeOfHeaders).ToArray());

            Log.Debug("Mapping {SectionCount} sections", sections.Count);
            FFI.MapSections(hProcess, remoteBase, dllBytes, sections);

            Log.Debug("Applying relocations");
            ApplyRelocations(hProcess, remoteBase, dllBytes, nt, sections);

            Log.Debug("Resolving imports");
            ResolveImports(hProcess, remoteBase, dllBytes, nt, sections);

            Log.Debug("Setting final section protections");
            FFI.SetSectionProtections(hProcess, remoteBase, sections);

            Log.Debug("Flushing instruction cache & erasing headers");
            FFI.FlushInstructionCache(hProcess, remoteBase, nt.OptionalHeader.SizeOfImage);
            EraseHeaders(hProcess, remoteBase, nt.OptionalHeader.SizeOfHeaders);

            switch (mode)
            {
                case InjectionMode.ThreadHijacking hijack:
                    Log.Information("Hijacking thread to execute DllMain (debug privilege: {EnableDebug}, debug marker: {EnableMarker}, log stub: {LogStub})",
                        hijack.EnableDebugPrivilege, hijack.EnableDebugMarker, hijack.LogGeneratedStub);
                    var debugMarker = HijackFirstThread(pid, hProcess, remoteBase, nt, hijack);

                    if (debugMarker == nint.Zero)
                    {
                        Log.Warning("Failed to hijack any thread. Stopping injection.");
                        return;
                    }

                    if (hijack.EnableDebugMarker)
                    {
                        Thread.Sleep(hijack.DebugMarkerCheckDelay);
                        try
                        {
                            var markerValue = FFI.ReadMemory(hProcess, debugMarker, 8);
                            var value = BitConverter.ToUInt64(markerValue);
                            Log.Debug("Debug marker result: 0x{Value:X} (entry=0x1111111111111111, preDllMain=0x2222222222222222, postDllMain=0x1337DEADBEEFCAFE)", value);
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "Failed to read debug marker");
                        }
                    }
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
            UnlinkFromPEB(hProcess, remoteBase);
        }
        finally
        {
            Log.Information("Finished injecting – closing handle");
            FFI.CloseHandleSafe(hProcess);
        }
    }

    /// <summary>
    /// Applies PE relocations to patch absolute addresses for the new base address.
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
    /// Resolves DLL imports by writing function pointers into the Import Address Table.
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

            var hModuleRemote = FFI.GetModuleHandle(dllName);
            if (hModuleRemote == nint.Zero)
            {
                Log.Debug("{Dll} not loaded – calling LoadLibraryA", dllName);
                var bytes = System.Text.Encoding.ASCII.GetBytes(dllName + "\0");
                var strAddr = FFI.AllocateMemory(hProcess, (uint)bytes.Length, FFI.PAGE_READWRITE);
                FFI.WriteMemory(hProcess, strAddr, bytes);

                var loadLib = FFI.GetProcAddress(FFI.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                FFI.CreateRemoteThreadAndWait(hProcess, loadLib, strAddr, wait: false);
                FFI.FreeMemory(hProcess, strAddr);
            }

            int thunkIdx = 0;
            while (true)
            {
                uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
                int thunkOffset = RvaToOffset(thunkRva + (uint)(thunkIdx * 8), sections);
                ulong importRef = BitConverter.ToUInt64(localArr, thunkOffset);
                if (importRef == 0) break;

                nint funcPtr;
                string identifier;
                if ((importRef & 0x8000000000000000) != 0)
                {
                    ushort ordinal = (ushort)(importRef & 0xFFFF);
                    funcPtr = FFI.GetProcAddress(FFI.GetModuleHandle(dllName), ordinal);
                    identifier = "ordinal #" + ordinal;
                }
                else
                {
                    uint nameRva = (uint)(importRef & 0x7FFFFFFF_FFFFFFFF);
                    string funcName = ReadAnsiString(localArr, nameRva + 2, sections);
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
    /// Reads a null-terminated ANSI string from the PE image at the specified RVA.
    /// </summary>
    private static string ReadAnsiString(byte[] image, uint rva, IReadOnlyList<FFI.IMAGE_SECTION_HEADER> sections)
    {
        int offset = RvaToOffset(rva, sections);
        int len = 0;
        while (image[offset + len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(image.AsSpan(offset, len));
    }

    /// <summary>
    /// Converts a Relative Virtual Address to file offset using section headers.
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
        return (int)rva;
    }

    /// <summary>
    /// Zeroes PE headers in remote memory for basic stealth.
    /// </summary>
    private static void EraseHeaders(nint hProcess, nint remoteBase, uint headerSize)
    {
        var zeros = new byte[headerSize];
        FFI.ProtectMemory(hProcess, remoteBase, headerSize, FFI.PAGE_READWRITE);
        FFI.WriteMemory(hProcess, remoteBase, zeros);
    }

    /// <summary>
    /// Hijacks the first available thread to execute the loader stub.
    /// Prefers non-blocked threads but will wake blocked ones if needed.
    /// </summary>
    private static nint HijackFirstThread(int pid, nint hProcess, nint moduleBase, FFI.IMAGE_NT_HEADERS64 nt, InjectionMode.ThreadHijacking config)
    {
        var currentProcess = FFI.GetCurrentProcess();
        bool currentIs64 = FFI.IsProcess64Bit(currentProcess);
        bool targetIs64 = FFI.IsProcess64Bit(hProcess);

        Log.Debug("Architecture check: current process 64-bit={Current}, target process 64-bit={Target}", currentIs64, targetIs64);

        if (!targetIs64)
        {
            Log.Warning("Target process is 32-bit (WOW64). Thread-hijacking only supports x64");
            return nint.Zero;
        }

        if (config.EnableDebugPrivilege) FFI.EnableSeDebugPrivilege();

        using var snap = new ThreadSnapshot(pid);
        var (activeThread, blockedThread) = FindCandidateThreads(snap);

        return (activeThread, blockedThread) switch
        {
            ({ } active, _) => HijackThread(active, hProcess, moduleBase, nt, config, needsWakeup: false),
            (null, { } blocked) => HijackThread(blocked, hProcess, moduleBase, nt, config, needsWakeup: true),
            _ => throw new Exception("Failed to hijack any thread")
        };
    }

    private static (ThreadInfo? active, ThreadInfo? blocked) FindCandidateThreads(ThreadSnapshot snap)
    {
        ThreadInfo? firstBlocked = null;
        var threadsToDispose = new List<ThreadInfo>();
        int totalThreads = 0, accessibleThreads = 0, validRipThreads = 0;

        try
        {
            foreach (var thread in snap.EnumerateThreads())
            {
                totalThreads++;
                threadsToDispose.Add(thread);

                if (!thread.TryGetContext(out var ctx))
                {
                    Log.Verbose("Thread {Tid}: GetThreadContext failed", thread.Id);
                    continue;
                }
                accessibleThreads++;

                if (ctx.Rip == 0)
                {
                    Log.Verbose("Thread {Tid}: RIP is zero", thread.Id);
                    continue;
                }
                validRipThreads++;

                bool isBlocked = IsRipInSystemModule(ctx.Rip);
                Log.Verbose("Thread {Tid}: RIP=0x{Rip:X}, blocked={Blocked}", thread.Id, ctx.Rip, isBlocked);

                if (!isBlocked)
                {
                    threadsToDispose.Remove(thread);
                    Log.Debug("Found active thread {Tid}", thread.Id);
                    return (thread, null);
                }

                if (firstBlocked == null)
                {
                    firstBlocked = thread;
                    threadsToDispose.Remove(thread);
                    Log.Debug("Found blocked thread {Tid} as fallback", thread.Id);
                }
            }

            Log.Information("Thread scan: {Total} total, {Accessible} accessible, {ValidRip} valid RIP, active={HasActive}, blocked={BlockedId}",
                totalThreads, accessibleThreads, validRipThreads, firstBlocked == null, firstBlocked?.Id ?? 0);
            return (null, firstBlocked);
        }
        finally
        {
            foreach (var thread in threadsToDispose)
                thread.Dispose();
        }
    }

    private static nint HijackThread(ThreadInfo thread, nint hProcess, nint moduleBase, FFI.IMAGE_NT_HEADERS64 nt, InjectionMode.ThreadHijacking config, bool needsWakeup)
    {
        try
        {
            if (!thread.TryGetContext(out var ctx))
                throw new Exception($"Failed to get context for thread {thread.Id}");

            var (stubAddr, debugMarker) = BuildAndWriteLoaderStub(hProcess, moduleBase, nt, (nint)ctx.Rip, config);

            ctx.Rip = (ulong)stubAddr;
            if (!thread.TrySetContext(ctx))
                throw new Exception($"Failed to set context for thread {thread.Id}");

            thread.ResumeCompletely();

            if (needsWakeup) WakeThread(thread.Id, thread.Handle);

            Log.Debug("Hijacked thread {Tid} (RIP: 0x{Rip:X} -> 0x{Stub:X})", thread.Id, ctx.Rip, (ulong)stubAddr);
            return debugMarker;
        }
        finally
        {
            thread.Dispose();
        }
    }

    private readonly record struct ThreadInfo(uint Id, nint Handle)
    {
        public bool TryGetContext(out FFI.CONTEXT64 ctx)
        {
            ctx = default;
            var suspend = FFI.SuspendThread(Handle);
            if (suspend == 0xFFFFFFFF)
            {
                Log.Verbose("Thread {Tid}: SuspendThread failed (err {Err})", Id, Marshal.GetLastWin32Error());
                return false;
            }

            if (!FFI.TryGetThreadContext(Handle, out ctx))
            {
                FFI.ResumeThread(Handle);
                return false;
            }

            return true;
        }

        public bool TrySetContext(FFI.CONTEXT64 ctx)
        {
            bool success = FFI.TrySetThreadContext(Handle, ctx);
            if (!success)
                FFI.ResumeThread(Handle);
            return success;
        }

        public void ResumeCompletely()
        {
            uint count;
            do { count = FFI.ResumeThread(Handle); }
            while (count > 0 && count != 0xFFFFFFFF);
        }

        public void Dispose()
        {
            uint cnt;
            do { cnt = FFI.ResumeThread(Handle); } while (cnt > 0 && cnt != 0xFFFFFFFF);
            FFI.CloseHandleSafe(Handle);
        }
    }

    private sealed class ThreadSnapshot : IDisposable
    {
        private readonly nint _handle;
        private readonly int _pid;

        public ThreadSnapshot(int pid)
        {
            _pid = pid;
            _handle = FFI.CreateToolhelp32Snapshot(FFI.TH32CS_SNAPTHREAD, 0);
            if (_handle == nint.Zero) throw new System.ComponentModel.Win32Exception();
        }

        public IEnumerable<ThreadInfo> EnumerateThreads()
        {
            var entry = new FFI.THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<FFI.THREADENTRY32>() };

            if (!FFI.Thread32First(_handle, ref entry)) yield break;

            do
            {
                if (entry.th32OwnerProcessID != (uint)_pid) continue;

                var hThread = FFI.OpenThread(FFI.THREAD_ALL_ACCESS, false, entry.th32ThreadID);
                if (hThread == nint.Zero) continue;

                var threadInfo = new ThreadInfo(entry.th32ThreadID, hThread);
                yield return threadInfo;
            }
            while (FFI.Thread32Next(_handle, ref entry));
        }

        public void Dispose() => FFI.CloseHandleSafe(_handle);
    }

    /// <summary>
    /// Creates and writes a loader stub that calls TLS callbacks and DllMain, then returns to original execution.
    /// </summary>
    private static (nint stubAddress, nint debugMarkerAddress) BuildAndWriteLoaderStub(nint hProcess, nint moduleBase, FFI.IMAGE_NT_HEADERS64 nt, nint originalRip, InjectionMode.ThreadHijacking config)
    {
        var dllMain = moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint;

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

        var arrBytes = new List<byte>();
        foreach (var c in callbacks) arrBytes.AddRange(BitConverter.GetBytes(c));
        arrBytes.AddRange(BitConverter.GetBytes((ulong)0));
        var callbacksRemote = FFI.AllocateMemory(hProcess, (uint)arrBytes.Count, FFI.PAGE_READWRITE);
        FFI.WriteMemory(hProcess, callbacksRemote, [.. arrBytes]);

        nint debugMarker = nint.Zero;
        if (config.EnableDebugMarker)
        {
            debugMarker = FFI.AllocateMemory(hProcess, 8, FFI.PAGE_READWRITE);
            FFI.WriteMemory(hProcess, debugMarker, BitConverter.GetBytes(0xDEADBEEFCAFEBABEUL));
            Log.Debug("Debug marker at 0x{Marker:X} (should change to 0x1337DEADBEEFCAFE after DllMain)", (ulong)debugMarker);
        }

        byte[] stub = BuildStubBytes((ulong)moduleBase, (ulong)dllMain, (ulong)callbacksRemote, (ulong)originalRip, (ulong)debugMarker);
        Log.Debug("Loader stub size {Size} bytes", stub.Length);

        if (config.LogGeneratedStub)
        {
            Log.Information("Generated stub bytes: {StubHex}", Convert.ToHexString(stub));
        }

        var remote = FFI.AllocateMemory(hProcess, (uint)stub.Length, FFI.PAGE_EXECUTE_READWRITE);
        FFI.WriteMemory(hProcess, remote, stub);
        FFI.ProtectMemory(hProcess, remote, (uint)stub.Length, FFI.PAGE_EXECUTE_READ);
        FFI.FlushInstructionCache(hProcess, remote, (uint)stub.Length);

        return (remote, debugMarker);
    }

    /// <summary>
    /// Generates x64 assembly stub that calls TLS callbacks, DllMain, and jumps to original RIP.
    /// </summary>
    private static byte[] BuildStubBytes(ulong moduleBase, ulong dllMain, ulong callbacksAddr, ulong originalRip, ulong debugMarker)
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

        if (debugMarker != 0)
        {
            MovRegImm64(0, debugMarker);
            MovRegImm64(1, 0x1111111111111111UL);
            Emit(0x48, 0x89, 0x08);
        }

        Emit(0x50);
        Emit(0x51);
        Emit(0x52);
        Emit(0x41, 0x50);
        Emit(0x53);

        Emit(0x48, 0x83, 0xEC, 0x20);

        if (callbacksAddr != 0)
        {
            MovRegImm64(3, callbacksAddr);
            int loopLabel = b.Count;
            Emit(0x48, 0x8B, 0x03);
            Emit(0x48, 0x85, 0xC0);
            Emit(0x74, 0x00); int jePos = b.Count - 1;

            MovRegImm64(1, moduleBase);
            Emit(0xBA, 0x01, 0x00, 0x00, 0x00);
            Emit(0x41, 0x31, 0xC0);
            Emit(0xFF, 0xD0);

            Emit(0x48, 0x83, 0xC3, 0x08);
            Emit(0xEB, (byte)(loopLabel - (b.Count + 1)));

            b[jePos] = (byte)(b.Count - (jePos + 1));
        }

        if (debugMarker != 0)
        {
            MovRegImm64(0, debugMarker);
            MovRegImm64(1, 0x2222222222222222UL);
            Emit(0x48, 0x89, 0x08);
        }

        MovRegImm64(1, moduleBase);
        Emit(0xBA, 0x01, 0x00, 0x00, 0x00);
        Emit(0x41, 0x31, 0xC0);
        MovRegImm64(0, dllMain);
        Emit(0xFF, 0xD0);

        if (debugMarker != 0)
        {
            MovRegImm64(0, debugMarker);
            MovRegImm64(1, 0x1337DEADBEEFCAFEUL);
            Emit(0x48, 0x89, 0x08);
        }

        Emit(0x48, 0x83, 0xC4, 0x20);
        Emit(0x5B);
        Emit(0x41, 0x58);
        Emit(0x5A);
        Emit(0x59);
        Emit(0x58);

        if (originalRip == 0)
        {
            Emit(0xC3);
        }
        else
        {
            MovRegImm64(0, originalRip);
            Emit(0xFF, 0xE0);
        }

        return [.. b];
    }

    /// <summary>
    /// Unlinks the mapped module from PEB lists for basic stealth.
    /// </summary>
    private static void UnlinkFromPEB(nint hProcess, nint moduleBase)
    {
        var status = FFI.NtQueryInformationProcess(hProcess, FFI.PROCESSINFOCLASS.ProcessBasicInformation, out var pbi, Marshal.SizeOf<FFI.PROCESS_BASIC_INFORMATION>(), out _);
        if (status != 0) return;

        nint peb = pbi.PebBaseAddress;
        const int offsetLdr = 0x18;
        const int offsetInLoadOrder = 0x10;
        const int entryOffsetDllBase = 0x30;
        const int entryOffsetInLoad = 0x00;
        const int entryOffsetInMem = 0x10;
        const int entryOffsetInInit = 0x20;

        byte[] buf8 = new byte[8];
        FFI.ReadProcessMemory(hProcess, peb + offsetLdr, buf8, 8, out _);
        nint ldr = (nint)BitConverter.ToInt64(buf8);
        FFI.ReadProcessMemory(hProcess, ldr + offsetInLoadOrder, buf8, 8, out _);
        nint listHead = (nint)BitConverter.ToInt64(buf8);
        nint current = listHead;
        int safety = 0;

        while (safety++ < 256)
        {
            byte[] dllBuf = new byte[8];
            FFI.ReadProcessMemory(hProcess, current + entryOffsetDllBase, dllBuf, 8, out _);
            nint dllBaseRead = (nint)BitConverter.ToInt64(dllBuf);
            if (dllBaseRead == moduleBase)
            {
                void Unlink(int offset)
                {
                    byte[] flinkBuf = new byte[8];
                    byte[] blinkBuf = new byte[8];
                    FFI.ReadProcessMemory(hProcess, current + offset, flinkBuf, 8, out _);
                    FFI.ReadProcessMemory(hProcess, current + offset + 8, blinkBuf, 8, out _);
                    nint flink = (nint)BitConverter.ToInt64(flinkBuf);
                    nint blink = (nint)BitConverter.ToInt64(blinkBuf);
                    FFI.WriteMemory(hProcess, blink, BitConverter.GetBytes((ulong)flink));
                    FFI.WriteMemory(hProcess, flink + 8, BitConverter.GetBytes((ulong)blink));
                }

                Unlink(entryOffsetInLoad);
                Unlink(entryOffsetInMem);
                Unlink(entryOffsetInInit);
                break;
            }

            FFI.ReadProcessMemory(hProcess, current, buf8, 8, out _);
            current = (nint)BitConverter.ToInt64(buf8);
            if (current == listHead || current == nint.Zero) break;
        }
    }

    /// <summary>
    /// Creates a wrapper stub that calls DllMain with proper parameters for CreateRemoteThread.
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

        Emit(0x48, 0x83, 0xEC, 0x28);

        MovRegImm64(1, moduleBase);
        Emit(0xBA, 0x01, 0x00, 0x00, 0x00);
        Emit(0x41, 0x31, 0xC0);
        MovRegImm64(0, dllMain);
        Emit(0xFF, 0xD0);

        Emit(0x48, 0x83, 0xC4, 0x28);
        Emit(0xC3);

        var stub = b.ToArray();
        var remote = FFI.AllocateMemory(hProcess, (uint)stub.Length, FFI.PAGE_EXECUTE_READWRITE);
        FFI.WriteMemory(hProcess, remote, stub);
        FFI.ProtectMemory(hProcess, remote, (uint)stub.Length, FFI.PAGE_EXECUTE_READ);
        FFI.FlushInstructionCache(hProcess, remote, (uint)stub.Length);
        return remote;
    }

    /// <summary>
    /// Heuristic check for whether RIP points inside common system modules.
    /// </summary>
    private static bool IsRipInSystemModule(ulong rip)
    {
        foreach (var (baseAddr, size) in _systemModuleRanges)
        {
            if (rip >= baseAddr && rip < baseAddr + size) return true;
        }
        return false;
    }

    private static readonly (ulong baseAddr, ulong size)[] _systemModuleRanges = InitRanges();

    private static (ulong, ulong)[] InitRanges()
    {
        string[] names = ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "win32u.dll"];
        List<(ulong, ulong)> list = [];
        foreach (var name in names)
        {
            var h = FFI.GetModuleHandle(name);
            if (h != nint.Zero)
            {
                list.Add(((ulong)h, 0x400000UL));
            }
        }
        return [.. list];
    }

    /// <summary>
    /// Attempts to wake a blocked thread using PostThreadMessage and NtAlertThread.
    /// </summary>
    private static void WakeThread(uint tid, nint hThread)
    {
        const uint WM_NULL = 0x0000;
        FFI.PostThreadMessage(tid, WM_NULL, 0, nint.Zero);
        FFI.NtAlertThread(hThread);
    }
}