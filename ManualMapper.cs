using System.Runtime.InteropServices;
using Serilog;

using ManualImageMapper.Interop;
using static ManualImageMapper.Interop.Win32;
using static ManualImageMapper.Interop.Win32.Const;
using static ManualImageMapper.Interop.Structures;

namespace ManualImageMapper;

/// <summary>
/// Injection mode configuration for manual DLL mapping.
/// </summary>
public abstract record InjectionMode
{
    /// <summary>
    /// Thread hijacking mode: suspends an existing thread, redirects RIP to our stub,
    /// then resumes. More stealthy as no new thread is created. The host polls a
    /// completion sentinel to know when the stub finished, then erases + frees all
    /// target-side allocations (stub, TLS callbacks, marker, LDR entry).
    /// </summary>
    /// <param name="WaitTimeout">Max time to poll for stub completion. <see cref="TimeSpan.Zero"/> uses the 5s default.</param>
    /// <param name="EnableDebugPrivilege">Acquire SeDebugPrivilege before opening protected processes.</param>
    /// <param name="LogStubBytes">Hex-dump generated shellcode for diagnostics.</param>
    public sealed record ThreadHijacking(
        TimeSpan WaitTimeout = default,
        bool EnableDebugPrivilege = true,
        bool LogStubBytes = false) : InjectionMode;

    /// <summary>
    /// CreateRemoteThread mode: spawns a new thread to execute the loader stub.
    /// Simpler but more detectable.
    /// </summary>
    public sealed record CreateRemoteThread(uint TimeoutMs = 30_000) : InjectionMode;
}

/// <summary>
/// Manual PE image mapper for x64 Windows. Injects DLLs without LoadLibrary by performing
/// all loader duties: section mapping, relocations, imports, TLS, and DllMain execution.
/// </summary>
public static partial class ManualMapper
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(ManualMapper));

    /// <summary>
    /// Pair of <c>LdrLockLoaderLock</c> / <c>LdrUnlockLoaderLock</c> addresses.
    /// Both are exported by ntdll.dll and reside at the same address in every process
    /// in a session, so locally-resolved values are valid in any target.
    /// </summary>
    private readonly record struct LoaderLockFns(nint Lock, nint Unlock);

    private static LoaderLockFns ResolveLoaderLockFns()
    {
        var ntdll = GetModuleHandle("ntdll.dll");
        if (ntdll == nint.Zero)
            throw new InvalidOperationException("ntdll.dll not loaded in current process - cannot resolve loader lock APIs");

        var lockFn = GetProcAddress(ntdll, "LdrLockLoaderLock");
        var unlockFn = GetProcAddress(ntdll, "LdrUnlockLoaderLock");
        if (lockFn == nint.Zero || unlockFn == nint.Zero)
            throw new InvalidOperationException("ntdll!Ldr{Lock,Unlock}LoaderLock not found");

        return new LoaderLockFns(lockFn, unlockFn);
    }

    /// <summary>
    /// Injects a DLL into the target process using manual mapping.
    /// </summary>
    public static void Inject(byte[] dllBytes, int pid, InjectionMode mode, string? dllName = null)
    {
        var nt = GetNtHeaders(dllBytes);
        var sections = GetSectionHeaders(dllBytes);
        dllName ??= "injected.dll";

        var loaderFns = ResolveLoaderLockFns();

        Log.Information("Opening target process {Pid}", pid);
        var hProcess = OpenTargetProcess(pid);
        nint remoteBase = nint.Zero;
        LdrStructures ldrStructures = LdrStructures.Empty;
        bool dllMainExecuted = false;

        try
        {
            if (!IsProcess64Bit(hProcess))
                throw new InvalidOperationException(
                    $"Target process {pid} is 32-bit; only x64 targets are supported.");

            Log.Debug("Allocating {Size} bytes in target", nt.OptionalHeader.SizeOfImage);
            remoteBase = AllocateMemory(hProcess, nt.OptionalHeader.SizeOfImage);

            Log.Debug("Copying headers ({HeaderSize} bytes)", nt.OptionalHeader.SizeOfHeaders);
            WriteMemory(hProcess, remoteBase, dllBytes.AsSpan(0, (int)nt.OptionalHeader.SizeOfHeaders).ToArray());

            Log.Debug("Mapping {SectionCount} sections", sections.Count);
            MapSections(hProcess, remoteBase, dllBytes, sections);

            Log.Debug("Applying relocations");
            ApplyRelocations(hProcess, remoteBase, dllBytes, nt, sections);

            Log.Debug("Resolving imports");
            ResolveImports(hProcess, remoteBase, dllBytes, nt, sections, pid);

            Log.Debug("Resolving delay-load imports");
            ResolveDelayLoadImports(hProcess, remoteBase, dllBytes, nt, sections, pid);

            RegisterExceptionHandlers(hProcess, remoteBase, dllBytes, nt, sections);

            Log.Debug("Setting final section protections");
            SetSectionProtections(hProcess, remoteBase, sections);

            var dllEntryPoint = remoteBase + (int)nt.OptionalHeader.AddressOfEntryPoint;

            Log.Debug("Building LDR entry (stub will link/unlink under loader lock)");
            nint ldrpHandleTlsDataAddr;
            (ldrStructures, ldrpHandleTlsDataAddr) = InitializeCrtModulePebOnly(
                hProcess, pid, remoteBase, nt.OptionalHeader.SizeOfImage,
                dllEntryPoint, nt.OptionalHeader.ImageBase, dllName);

            if (!ldrStructures.IsEmpty)
                Log.Debug("LDR entry built - addr: 0x{Entry:X}", (ulong)ldrStructures.Allocations.LdrEntry);

            // Patch NativeAOT's PalGetModuleHandleFromPointer to handle our unmapped module
            PatchNativeAotModuleLookup(hProcess, remoteBase, dllBytes, nt.OptionalHeader.SizeOfImage);

            FlushInstructionCache(hProcess, remoteBase, nt.OptionalHeader.SizeOfImage);

            var dotnetMainAddr = GetExportRva(dllBytes, "DotnetMain") is int rva and > 0
                ? remoteBase + rva
                : nint.Zero;

            dllMainExecuted = mode switch
            {
                InjectionMode.ThreadHijacking hijack => ExecuteViaThreadHijacking(
                    hProcess, pid, remoteBase, nt, hijack, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrStructures, loaderFns),

                InjectionMode.CreateRemoteThread crt => ExecuteViaRemoteThread(
                    hProcess, remoteBase, nt, crt, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrStructures, loaderFns),

                _ => throw new ArgumentException($"Unsupported injection mode: {mode.GetType().Name}")
            };

            if (dllMainExecuted)
            {
                // Stub already unlinked under loader lock - just free the allocations.
                Log.Debug("Freeing PEB allocations");
                FreePebLinkAllocations(hProcess, ldrStructures.Allocations);
                ldrStructures = LdrStructures.Empty;
            }
            else
            {
                Log.Warning("DllMain did not signal completion - leaking allocations to avoid corrupting in-flight stub");
            }
        }
        catch
        {
            if (!dllMainExecuted)
            {
                Log.Debug("Freeing remote memory due to injection failure");
                if (remoteBase != nint.Zero) try { FreeMemory(hProcess, remoteBase); } catch { }
                try { FreePebLinkAllocations(hProcess, ldrStructures.Allocations); } catch { }
            }
            throw;
        }
        finally
        {
            if (dllMainExecuted)
                Log.Information("Injection complete");
            else
                Log.Warning("Injection did not complete successfully");
            CloseHandleSafe(hProcess);
        }
    }

    private static bool ExecuteViaThreadHijacking(
        nint hProcess, int pid, nint remoteBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.ThreadHijacking config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr,
        LdrStructures ldrStructures, LoaderLockFns loaderFns)
    {
        var timeout = config.WaitTimeout > TimeSpan.Zero ? config.WaitTimeout : TimeSpan.FromSeconds(5);
        Log.Information("Using thread hijacking (timeout: {Timeout})", timeout);

        var stubInfo = HijackFirstThread(
            pid, hProcess, remoteBase, nt, config, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrStructures, loaderFns);

        var completed = WaitForCompletion(hProcess, stubInfo.MarkerAddr, timeout, out var lastValue);

        if (!completed)
        {
            Log.Warning("Hijack stub did not signal completion in {Timeout} (last stage: {Stage}); leaking allocations to avoid corrupting in-flight stub",
                timeout, FormatStage(lastValue));
            return false;
        }

        Log.Debug("Hijack stub signaled completion; final stage: {Stage}", FormatStage(lastValue));

        // Grace period: stub still has ~50 bytes of register restoration + RIP-relative jmp
        // to execute after writing the marker. 50ms is six orders of magnitude more than needed.
        Thread.Sleep(50);

        Log.Debug("Cleaning up target-side allocations");
        EraseAndFree(hProcess, stubInfo.StubAddr, stubInfo.StubLen);
        if (stubInfo.CallbacksAddr != nint.Zero)
            EraseAndFree(hProcess, stubInfo.CallbacksAddr, stubInfo.CallbacksLen);
        TryFreeRemote(hProcess, stubInfo.MarkerAddr);

        return true;
    }

    private static bool ExecuteViaRemoteThread(
        nint hProcess, nint remoteBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.CreateRemoteThread config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr,
        LdrStructures ldrStructures, LoaderLockFns loaderFns)
    {
        Log.Information("Using CreateRemoteThread (timeout: {TimeoutMs}ms)", config.TimeoutMs);

        var (wrapper, wrapperLen, callbacksAddr, callbacksLen) = BuildDllMainWrapper(
            hProcess, remoteBase, nt, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrStructures, loaderFns);

        try
        {
            var hThread = CreateRemoteThreadAndWait(hProcess, wrapper, nint.Zero, wait: false);
            if (hThread == nint.Zero) return false;

            WaitForSingleObject(hThread, config.TimeoutMs);
            CloseHandleSafe(hThread);
            return true;
        }
        finally
        {
            EraseAndFree(hProcess, wrapper, wrapperLen);
            if (callbacksAddr != nint.Zero)
                EraseAndFree(hProcess, callbacksAddr, callbacksLen);
        }
    }

    /// <summary>
    /// Polls the sync marker in the target process for <see cref="SYNC_MARKER_DONE"/>.
    /// </summary>
    private static bool WaitForCompletion(nint hProcess, nint markerAddr, TimeSpan timeout, out ulong lastValue)
    {
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        lastValue = DEBUG_MARKER_INITIAL;
        while (Environment.TickCount64 < deadline)
        {
            try
            {
                lastValue = BitConverter.ToUInt64(ReadMemory(hProcess, markerAddr, 8));
                if (lastValue == SYNC_MARKER_DONE) return true;
            }
            catch
            {
                // Transient read failure (e.g., target ASLR'd a page mid-poll); retry.
            }
            Thread.Sleep(5);
        }
        return false;
    }

    private static string FormatStage(ulong value) =>
        (value >> 32) == 0x5555
            ? $"LdrpHandleTlsData returned 0x{value & 0xFFFFFFFF:X8}"
            : value switch
            {
                DEBUG_MARKER_INITIAL => "INITIAL (stub never ran)",
                DEBUG_MARKER_ENTRY => "ENTRY",
                DEBUG_MARKER_POST_TLS => "POST_TLS",
                DEBUG_MARKER_PRE_DLLMAIN => "PRE_DLLMAIN",
                DEBUG_MARKER_POST_DLLMAIN => "POST_DLLMAIN",
                DEBUG_MARKER_POST_PEB_UNLINK => "POST_PEB_UNLINK",
                DEBUG_MARKER_POST_LOCK_RELEASE => "POST_LOCK_RELEASE",
                DEBUG_MARKER_POST_DOTNETMAIN => "POST_DOTNETMAIN",
                SYNC_MARKER_DONE => "DONE",
                _ => $"UNKNOWN (0x{value:X})"
            };

    /// <summary>
    /// Zeros remote memory then frees it. Safe to call once the stub has signaled completion;
    /// the zeroing scrubs shellcode bytes from any future memory dump of the target.
    /// </summary>
    private static void EraseAndFree(nint hProcess, nint addr, int len)
    {
        if (addr == nint.Zero || len <= 0) return;
        try
        {
            ProtectMemory(hProcess, addr, (uint)len, PAGE_READWRITE);
            WriteMemory(hProcess, addr, new byte[len]);
            FreeMemory(hProcess, addr);
        }
        catch (Exception ex)
        {
            Log.Verbose(ex, "EraseAndFree failed for 0x{Addr:X} ({Len})", (ulong)addr, len);
        }
    }

    private static void TryFreeRemote(nint hProcess, nint addr)
    {
        if (addr == nint.Zero) return;
        try { FreeMemory(hProcess, addr); }
        catch (Exception ex) { Log.Verbose(ex, "TryFreeRemote failed for 0x{Addr:X}", (ulong)addr); }
    }

    #region PE Operations

    private static void ApplyRelocations(
        nint hProcess, nint remoteBase, ReadOnlySpan<byte> image,
        IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        var relocDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.BASERELOC];
        if (relocDir.Size == 0) return;

        var delta = remoteBase.ToInt64() - (long)nt.OptionalHeader.ImageBase;
        var imageArr = image.ToArray();
        int processed = 0;
        int relocBaseOffset = RvaToOffset(relocDir.VirtualAddress, sections, imageArr.Length);

        while (processed < relocDir.Size)
        {
            int blockOffset = relocBaseOffset + processed;
            var reloc = BytesToStructure<IMAGE_BASE_RELOCATION>(imageArr, blockOffset);
            processed += Marshal.SizeOf<IMAGE_BASE_RELOCATION>();

            int entryCount = ((int)reloc.SizeOfBlock - Marshal.SizeOf<IMAGE_BASE_RELOCATION>()) / 2;

            for (int i = 0; i < entryCount; i++)
            {
                ushort entry = BitConverter.ToUInt16(imageArr, relocBaseOffset + processed + i * 2);
                int type = entry >> 12;
                int offset = entry & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64)
                {
                    var addr = remoteBase + (int)reloc.VirtualAddress + offset;
                    var orig = BitConverter.ToUInt64(ReadMemory(hProcess, addr, 8));
                    WriteMemory(hProcess, addr, BitConverter.GetBytes(orig + (ulong)delta));
                }
            }
            processed += entryCount * 2;
        }
    }

    private static void ResolveImports(
        nint hProcess, nint remoteBase, ReadOnlySpan<byte> image,
        IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections, int pid)
    {
        var importDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.IMPORT];
        if (importDir.Size == 0) return;

        var imageArr = image.ToArray();
        int descSize = Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();

        for (int idx = 0; ; idx++)
        {
            int descOffset = RvaToOffset(importDir.VirtualAddress + (uint)(idx * descSize), sections, imageArr.Length);
            var desc = BytesToStructure<IMAGE_IMPORT_DESCRIPTOR>(imageArr, descOffset);
            if (desc.Name == 0) break;

            string dllName = ReadAnsiString(imageArr, desc.Name, sections);
            var hModule = GetRemoteModuleHandle(hProcess, pid, dllName);
            if (hModule == nint.Zero)
                hModule = LoadLibraryRemote(hProcess, dllName);

            if (hModule == nint.Zero)
            {
                Log.Warning("Failed to load {Dll}", dllName);
                continue;
            }

            ResolveImportThunks(hProcess, remoteBase, imageArr, sections, desc, hModule, dllName, pid);
        }
    }

    private static void ResolveImportThunks(
        nint hProcess, nint remoteBase, byte[] image,
        IReadOnlyList<IMAGE_SECTION_HEADER> sections,
        IMAGE_IMPORT_DESCRIPTOR desc, nint hModule, string dllName, int pid)
    {
        for (int i = 0; ; i++)
        {
            uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            int thunkOffset = RvaToOffset(thunkRva + (uint)(i * 8), sections, image.Length);
            ulong importRef = BitConverter.ToUInt64(image, thunkOffset);
            if (importRef == 0) break;

            nint funcPtr;
            if ((importRef & IMAGE_ORDINAL_FLAG64) != 0)
            {
                funcPtr = GetRemoteProcAddressByOrdinal(hProcess, hModule, (ushort)(importRef & 0xFFFF));
            }
            else
            {
                uint nameRva = (uint)(importRef & IMAGE_THUNK_RVA_MASK64);
                string funcName = ReadAnsiString(image, nameRva + 2, sections);
                funcPtr = GetRemoteProcAddress(hProcess, hModule, funcName, pid);
            }

            var iatEntry = remoteBase + (int)desc.FirstThunk + i * sizeof(ulong);
            WriteMemory(hProcess, iatEntry, BitConverter.GetBytes((ulong)funcPtr));
        }
    }

    private static void ResolveDelayLoadImports(
        nint hProcess, nint remoteBase, ReadOnlySpan<byte> image,
        IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections, int pid)
    {
        var delayDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.DELAY_IMPORT];
        if (delayDir.Size == 0) return;

        var imageArr = image.ToArray();
        int descSize = Marshal.SizeOf<IMAGE_DELAYLOAD_DESCRIPTOR>();

        for (int idx = 0; ; idx++)
        {
            int descOffset = RvaToOffset(delayDir.VirtualAddress + (uint)(idx * descSize), sections, imageArr.Length);
            var desc = BytesToStructure<IMAGE_DELAYLOAD_DESCRIPTOR>(imageArr, descOffset);
            if (desc.DllNameRVA == 0) break;

            string dllName = ReadAnsiString(imageArr, desc.DllNameRVA, sections);
            var hModule = GetRemoteModuleHandle(hProcess, pid, dllName);
            if (hModule == nint.Zero)
                hModule = LoadLibraryRemote(hProcess, dllName);

            if (hModule == nint.Zero)
            {
                Log.Warning("Failed to load delay-load {Dll}", dllName);
                continue;
            }

            if (desc.ModuleHandleRVA != 0)
                WriteMemory(hProcess, remoteBase + (int)desc.ModuleHandleRVA, BitConverter.GetBytes((ulong)hModule));

            ResolveDelayImportThunks(hProcess, remoteBase, imageArr, sections, desc, hModule, dllName, pid);
        }
    }

    private static void ResolveDelayImportThunks(
        nint hProcess, nint remoteBase, byte[] image,
        IReadOnlyList<IMAGE_SECTION_HEADER> sections,
        IMAGE_DELAYLOAD_DESCRIPTOR desc, nint hModule, string dllName, int pid)
    {
        for (int i = 0; ; i++)
        {
            int intOffset = RvaToOffset(desc.ImportNameTableRVA + (uint)(i * 8), sections, image.Length);
            ulong importRef = BitConverter.ToUInt64(image, intOffset);
            if (importRef == 0) break;

            nint funcPtr;
            if ((importRef & IMAGE_ORDINAL_FLAG64) != 0)
            {
                funcPtr = GetRemoteProcAddressByOrdinal(hProcess, hModule, (ushort)(importRef & 0xFFFF));
            }
            else
            {
                uint nameRva = (uint)(importRef & IMAGE_THUNK_RVA_MASK64);
                string funcName = ReadAnsiString(image, nameRva + 2, sections);
                funcPtr = GetRemoteProcAddress(hProcess, hModule, funcName, pid);
            }

            var iatEntry = remoteBase + (int)desc.ImportAddressTableRVA + i * sizeof(ulong);
            WriteMemory(hProcess, iatEntry, BitConverter.GetBytes((ulong)funcPtr));
        }
    }

    private static string ReadAnsiString(byte[] image, uint rva, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        int offset = RvaToOffset(rva, sections, image.Length);
        int len = 0;
        while (offset + len < image.Length && image[offset + len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(image.AsSpan(offset, len));
    }

    private static int RvaToOffset(uint rva, IReadOnlyList<IMAGE_SECTION_HEADER> sections, int imageSize)
    {
        foreach (var section in sections)
        {
            var end = section.VirtualAddress + Math.Max(section.SizeOfRawData, section.VirtualSize);
            if (rva >= section.VirtualAddress && rva < end)
            {
                int offset = (int)(rva - section.VirtualAddress + section.PointerToRawData);
                return offset < imageSize ? offset : throw new InvalidOperationException($"Invalid RVA 0x{rva:X}");
            }
        }

        if (rva < imageSize && sections.Count > 0 && rva < sections[0].VirtualAddress)
            return (int)rva;

        throw new InvalidOperationException($"RVA 0x{rva:X} not found");
    }

    private static int? GetExportRva(byte[] pe, string exportName)
    {
        try
        {
            var dos = BytesToStructure<IMAGE_DOS_HEADER>(pe, 0);
            if (dos.e_magic != IMAGE_DOS_SIGNATURE) return null;

            var nt = BytesToStructure<IMAGE_NT_HEADERS64>(pe, dos.e_lfanew);
            var exportDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.EXPORT];
            if (exportDir.Size == 0) return null;

            var sections = GetSectionHeaders(pe);
            int exportOffset = RvaToOffset(exportDir.VirtualAddress, sections, pe.Length);
            var exports = BytesToStructure<IMAGE_EXPORT_DIRECTORY>(pe, exportOffset);
            if (exports.NumberOfNames == 0) return null;

            int namesOffset = RvaToOffset(exports.AddressOfNames, sections, pe.Length);
            int ordinalsOffset = RvaToOffset(exports.AddressOfNameOrdinals, sections, pe.Length);
            int funcsOffset = RvaToOffset(exports.AddressOfFunctions, sections, pe.Length);

            for (uint i = 0; i < exports.NumberOfNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(pe, namesOffset + (int)(i * 4));
                int nameOffset = RvaToOffset(nameRva, sections, pe.Length);

                int len = 0;
                while (nameOffset + len < pe.Length && pe[nameOffset + len] != 0) len++;
                var name = System.Text.Encoding.ASCII.GetString(pe, nameOffset, len);

                if (name == exportName)
                {
                    ushort ordinal = BitConverter.ToUInt16(pe, ordinalsOffset + (int)(i * 2));
                    uint funcRva = BitConverter.ToUInt32(pe, funcsOffset + ordinal * 4);

                    if (funcRva >= exportDir.VirtualAddress && funcRva < exportDir.VirtualAddress + exportDir.Size)
                        return null; // Forwarder

                    return (int)funcRva;
                }
            }
            return null;
        }
        catch { return null; }
    }

    #endregion

    #region Exception Handlers

    private static void RegisterExceptionHandlers(
        nint hProcess, nint remoteBase, ReadOnlySpan<byte> image,
        IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        var exceptionDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.EXCEPTION];
        if (exceptionDir.Size == 0) return;

        int entryCount = (int)(exceptionDir.Size / Marshal.SizeOf<IMAGE_RUNTIME_FUNCTION_ENTRY>());
        var remoteFunctionTable = remoteBase + (int)exceptionDir.VirtualAddress;

        var rtlAddFunctionTable = GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlAddFunctionTable");
        if (rtlAddFunctionTable == nint.Zero) return;

        var stub = new StubBuilder()
            .Sub_Rsp(0x28)
            .Mov_Reg_Imm64(1, (ulong)remoteFunctionTable)
            .Mov_Edx_Imm32((uint)entryCount)
            .Mov_Reg_Imm64(8, (ulong)remoteBase)
            .Mov_Reg_Imm64(0, (ulong)rtlAddFunctionTable)
            .Call_Rax()
            .Add_Rsp(0x28)
            .Ret()
            .Build();

        ExecuteRemoteStub(hProcess, stub);
        Log.Debug("Registered {Count} exception handlers", entryCount);
    }

    #endregion

    #region NativeAOT Support

    /// <summary>
    /// Replaces NativeAOT's <c>PalGetModuleHandleFromPointer</c> with a stub that returns our
    /// module base when called with a pointer in our DLL's range, and NULL otherwise.
    ///
    /// <para>Why this is needed: <c>PalGetModuleHandleFromPointer</c> is a thin wrapper around
    /// <c>GetModuleHandleExW(FROM_ADDRESS|PIN, p, &amp;hMod)</c>. The kernel's lookup uses
    /// <c>LdrpModuleBaseAddressIndex</c> (an RB tree the manual mapper does not update), so for
    /// a manually-mapped DLL the call returns NULL. The runtime then hangs in lazy init because
    /// it has no module handle.</para>
    ///
    /// <para>Detection signature: <c>B9 05 00 00 00 FF 15 ?? ?? ?? ??</c>
    /// (<c>mov ecx, 5</c> = FROM_ADDRESS|PIN flag combo, then <c>call qword ptr [rip+disp32]</c>
    /// = the IAT call to <c>GetModuleHandleExW</c>). This signature is highly distinctive — only
    /// one match exists in a typical NativeAOT shared library — and survives codegen changes
    /// (security cookies, frame size adjustments) since it keys on the call site, not the
    /// prologue.</para>
    ///
    /// <para>Hook layout (overwrites the original function in place — no prologue stealing,
    /// no relocation of RIP-relative instructions, no trampoline back to original):</para>
    /// <code>
    ///   mov rax, moduleBase
    ///   cmp rcx, rax
    ///   jb  null
    ///   mov rax, moduleEnd
    ///   cmp rcx, rax
    ///   jae null
    ///   mov rax, moduleBase     ; in-range: return our module base
    ///   ret
    ///  null:
    ///   xor eax, eax            ; out-of-range: return NULL (matches what the kernel would
    ///   ret                       ; return for a non-loaded address)
    /// </code>
    /// <para>NativeAOT only ever calls this with pointers inside its own runtime, so the
    /// out-of-range branch is defensive — it doesn't lose functionality for the runtime's needs.</para>
    /// </summary>
    private static void PatchNativeAotModuleLookup(nint hProcess, nint remoteBase, byte[] dll, uint sizeOfImage)
    {
        // Find the unique `mov ecx, 5; call qword ptr [rip+disp]` site, then walk back to the
        // function prologue (`sub rsp, imm8`). We work in FILE offsets while reading dll[] then
        // convert to RVA once for the runtime patch.
        var (callFileOff, sectionRvaDelta) = FindPalGetModuleHandleCallSite(dll);
        if (callFileOff < 0)
        {
            Log.Warning("PalGetModuleHandleFromPointer signature not found — NativeAOT runtime init will likely hang. Check codegen.");
            return;
        }

        int funcFileOff = -1;
        // Walk backwards looking for `sub rsp, imm8` (48 83 EC ??) preceded by CC/90 padding.
        for (int i = callFileOff - 1; i >= callFileOff - 256 && i >= 0; i--)
        {
            if (dll[i] == 0x48 && dll[i + 1] == 0x83 && dll[i + 2] == 0xEC)
            {
                if (i == 0 || dll[i - 1] == 0xCC || dll[i - 1] == 0x90)
                {
                    funcFileOff = i;
                    break;
                }
            }
        }
        if (funcFileOff < 0)
        {
            Log.Warning("PalGetModuleHandleFromPointer call site found at file offset 0x{Site:X} but couldn't locate function prologue.", callFileOff);
            return;
        }

        // Convert file offset → RVA (delta is the same for both since they're in the same section)
        int funcRva = funcFileOff + sectionRvaDelta;
        int callSiteRva = callFileOff + sectionRvaDelta;
        ulong funcAddr = (ulong)remoteBase + (uint)funcRva;
        ulong moduleEnd = (ulong)remoteBase + sizeOfImage;

        // Build the in-place replacement. 44 bytes total. Layout (offsets):
        //   0:  mov rax, moduleBase    (10)
        //   10: cmp rcx, rax           (3)
        //   13: jb 26 → null at 41     (2)
        //   15: mov rax, moduleEnd     (10)
        //   25: cmp rcx, rax           (3)
        //   28: jae 11 → null at 41    (2)
        //   30: mov rax, moduleBase    (10) — in-range, return base
        //   40: ret                    (1)
        //   41: xor eax, eax           (2) — null label
        //   43: ret                    (1)
        var stub = new StubBuilder()
            .Mov_Reg_Imm64(0, (ulong)remoteBase)
            .Cmp_Rcx_Rax()
            .Jb(26)
            .Mov_Reg_Imm64(0, moduleEnd)
            .Cmp_Rcx_Rax()
            .Jae(11)
            .Mov_Reg_Imm64(0, (ulong)remoteBase)
            .Ret()
            .Raw([0x33, 0xC0])
            .Ret()
            .Build();

        // Overwrite function entry. We need to ensure we don't write past the function (corrupting
        // the next function). The shortest path: the call site is 27 bytes from prologue start; we
        // need at most ~44 bytes for the hook. If hook fits within (callSiteRva - funcRva) + 7
        // (call instruction length) bytes, we're safe. If not, log a warning and refuse.
        int functionMinLen = (callSiteRva + 7) - funcRva; // includes the call instruction itself
        if (stub.Length > functionMinLen + 32) // generous slack — most functions tail-call/return after this
        {
            Log.Warning("Hook stub ({Len} bytes) may overflow PalGetModuleHandleFromPointer; not patching.", stub.Length);
            return;
        }

        var oldProtect = ProtectMemory(hProcess, (nint)funcAddr, (uint)stub.Length, PAGE_EXECUTE_READWRITE);
        WriteMemory(hProcess, (nint)funcAddr, stub);
        ProtectMemory(hProcess, (nint)funcAddr, (uint)stub.Length, oldProtect);
        FlushInstructionCache(hProcess, (nint)funcAddr, (nuint)stub.Length);

        Log.Information("Replaced PalGetModuleHandleFromPointer @0x{Func:X} with in-range hook for [0x{Start:X}, 0x{End:X})",
            funcAddr, (ulong)remoteBase, moduleEnd);
    }

    /// <summary>
    /// Search every executable section for the unique call-site signature
    /// <c>B9 05 00 00 00 FF 15 ?? ?? ?? ??</c> — <c>mov ecx, 5; call qword ptr [rip+disp32]</c>.
    /// Returns (fileOffset, sectionRvaDelta) where <c>fileOffset + sectionRvaDelta</c> = RVA.
    /// Returns (-1, 0) if not found.
    /// </summary>
    private static (int fileOffset, int sectionRvaDelta) FindPalGetModuleHandleCallSite(byte[] dll)
    {
        var sections = GetSectionHeaders(dll);
        foreach (var section in sections)
        {
            if ((section.Characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) == 0)
                continue;

            int start = (int)section.PointerToRawData;
            int end = start + (int)section.SizeOfRawData - 11;
            int delta = (int)section.VirtualAddress - (int)section.PointerToRawData;

            for (int i = start; i <= end; i++)
            {
                if (dll[i] == 0xB9
                    && dll[i + 1] == 0x05 && dll[i + 2] == 0x00 && dll[i + 3] == 0x00 && dll[i + 4] == 0x00
                    && dll[i + 5] == 0xFF && dll[i + 6] == 0x15)
                {
                    return (i, delta);
                }
            }
        }
        return (-1, 0);
    }

    private static int FindPattern(byte[] data, byte[] pattern)
    {
        var sections = GetSectionHeaders(data);
        foreach (var section in sections)
        {
            if ((section.Characteristics & (uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE) == 0)
                continue;

            int start = (int)section.PointerToRawData;
            int end = start + (int)section.SizeOfRawData - pattern.Length;

            for (int i = start; i <= end; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length && match; j++)
                    match = data[i + j] == pattern[j];

                if (match)
                    return i - (int)section.PointerToRawData + (int)section.VirtualAddress;
            }
        }
        return -1;
    }

    #endregion

    #region Thread Hijacking

    /// <summary>
    /// Tracks every target-side allocation made for a hijack so the host can erase + free them
    /// after the stub signals completion.
    /// </summary>
    private readonly record struct HijackStubInfo(
        nint StubAddr, int StubLen,
        nint CallbacksAddr, int CallbacksLen,
        nint MarkerAddr);

    private static HijackStubInfo HijackFirstThread(
        int pid, nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.ThreadHijacking config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr,
        LdrStructures ldrStructures, LoaderLockFns loaderFns)
    {
        if (config.EnableDebugPrivilege)
            EnableSeDebugPrivilege();

        using var snap = new ThreadSnapshot(pid);
        var (active, blocked) = FindCandidateThreads(snap);

        return (active, blocked) switch
        {
            ({ } t, _) => HijackThread(t, hProcess, moduleBase, nt, config, false, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrStructures, loaderFns),
            (_, { } t) => HijackThread(t, hProcess, moduleBase, nt, config, true, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrStructures, loaderFns),
            _ => throw new InvalidOperationException("No suitable thread found")
        };
    }

    private static (ThreadInfo? active, ThreadInfo? blocked) FindCandidateThreads(ThreadSnapshot snap)
    {
        ThreadInfo? blocked = null;
        var toDispose = new List<ThreadInfo>();

        try
        {
            foreach (var thread in snap.EnumerateThreads())
            {
                toDispose.Add(thread);

                if (!thread.TryGetContext(out var ctx) || ctx.Rip == 0)
                    continue;

                bool isBlocked = IsInSystemModule(ctx.Rip);

                if (!isBlocked)
                {
                    toDispose.Remove(thread);
                    return (thread, null);
                }

                if (blocked == null)
                {
                    blocked = thread;
                    toDispose.Remove(thread);
                }
            }
            return (null, blocked);
        }
        finally
        {
            foreach (var t in toDispose) t.Dispose();
        }
    }

    private static HijackStubInfo HijackThread(
        ThreadInfo thread, nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.ThreadHijacking config, bool needsWakeup,
        nint dotnetMainAddr, nint ldrpHandleTlsDataAddr,
        LdrStructures ldrStructures, LoaderLockFns loaderFns)
    {
        HijackStubInfo? built = null;
        try
        {
            if (!thread.TryGetContext(out var ctx))
                throw new InvalidOperationException($"Failed to get context for thread {thread.Id}");

            built = BuildAndWriteLoaderStub(
                hProcess, moduleBase, nt, (nint)ctx.Rip, config,
                dotnetMainAddr, ldrpHandleTlsDataAddr, ldrStructures, loaderFns);

            ctx.Rip = (ulong)built.Value.StubAddr;
            if (!thread.TrySetContext(ctx))
                throw new InvalidOperationException($"Failed to set context for thread {thread.Id}");

            thread.ResumeCompletely();
            if (needsWakeup) WakeThread(thread.Id, thread.Handle);

            Log.Debug("Hijacked thread {Tid}", thread.Id);
            return built.Value;
        }
        catch
        {
            // Stub was allocated but RIP not redirected; safe to free.
            if (built is { } info)
            {
                TryFreeRemote(hProcess, info.StubAddr);
                if (info.CallbacksAddr != nint.Zero) TryFreeRemote(hProcess, info.CallbacksAddr);
                TryFreeRemote(hProcess, info.MarkerAddr);
            }
            throw;
        }
        finally
        {
            thread.Dispose();
        }
    }

    private static HijackStubInfo BuildAndWriteLoaderStub(
        nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt, nint originalRip,
        InjectionMode.ThreadHijacking config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr,
        LdrStructures ldrStructures, LoaderLockFns loaderFns)
    {
        var dllMain = moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint;
        var callbacks = CollectTlsCallbacks(hProcess, moduleBase, nt);

        nint callbacksRemote = nint.Zero;
        int callbacksLen = 0;
        if (callbacks.Count > 0)
        {
            var cbBytes = callbacks.SelectMany(BitConverter.GetBytes).Concat(new byte[8]).ToArray();
            callbacksLen = cbBytes.Length;
            callbacksRemote = AllocateMemory(hProcess, (uint)callbacksLen, PAGE_READWRITE);
            WriteMemory(hProcess, callbacksRemote, cbBytes);
        }

        // Marker is always allocated - host polls it for sync, regardless of debug flags.
        var marker = AllocateMemory(hProcess, 8, PAGE_READWRITE);
        WriteMemory(hProcess, marker, BitConverter.GetBytes(DEBUG_MARKER_INITIAL));

        var stub = BuildHijackStub(
            (ulong)moduleBase, (ulong)dllMain, (ulong)callbacksRemote, (ulong)originalRip,
            (ulong)marker, nt.OptionalHeader.SizeOfHeaders,
            (ulong)dotnetMainAddr, (ulong)ldrpHandleTlsDataAddr,
            ldrStructures, loaderFns);

        if (config.LogStubBytes)
            Log.Information("Stub bytes ({Length}): {Hex}", stub.Length, Convert.ToHexString(stub));

        var stubAddr = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, stubAddr, stub);
        ProtectMemory(hProcess, stubAddr, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, stubAddr, (uint)stub.Length);

        return new HijackStubInfo(stubAddr, stub.Length, callbacksRemote, callbacksLen, marker);
    }

    private static List<ulong> CollectTlsCallbacks(nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt)
    {
        var callbacks = new List<ulong>();
        var tlsDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.TLS];
        if (tlsDir.Size == 0) return callbacks;

        var tlsBytes = ReadMemory(hProcess, moduleBase + (int)tlsDir.VirtualAddress, Marshal.SizeOf<IMAGE_TLS_DIRECTORY64>());
        var tls = BytesToStructure<IMAGE_TLS_DIRECTORY64>(tlsBytes, 0);

        if (tls.AddressOfCallBacks == 0) return callbacks;

        ulong ptr = tls.AddressOfCallBacks;
        for (int i = 0; i < MAX_TLS_CALLBACKS; i++)
        {
            ulong cb = BitConverter.ToUInt64(ReadMemory(hProcess, (nint)ptr, 8));
            if (cb == 0) break;
            callbacks.Add(cb);
            ptr += 8;
        }

        return callbacks;
    }

    /// <summary>
    /// Builds the thread hijacking stub that:
    /// <list type="number">
    /// <item>Saves complete CPU state (GPRs, flags, x87/SSE/AVX via XSAVE).</item>
    /// <item>Acquires <c>LdrLockLoaderLock</c> so all PEB-list and loader-callable work runs under the same lock the OS loader holds.</item>
    /// <item>Inserts the LDR entry into all three PEB module lists (load/memory/init order).</item>
    /// <item>Calls <c>LdrpHandleTlsData</c> to initialize TLS, then runs TLS callbacks and DllMain.</item>
    /// <item>Optionally calls DotnetMain export.</item>
    /// <item>Removes the entry from all three PEB lists and releases the loader lock.</item>
    /// <item>Erases PE headers for stealth.</item>
    /// <item>Writes <see cref="SYNC_MARKER_DONE"/> so the host can free target-side allocations.</item>
    /// <item>Restores CPU state and jumps back to original RIP.</item>
    /// </list>
    /// Stack layout after the prologue: [rsp+0x00..0x1F] shadow, [rsp+0x20] cookie, [rsp+0x28] state.
    /// </summary>
    private static byte[] BuildHijackStub(
        ulong moduleBase, ulong dllMain, ulong callbacksAddr, ulong originalRip,
        ulong markerAddr, uint headerSize, ulong dotnetMain, ulong ldrpHandleTlsData,
        LdrStructures ldrStructures, LoaderLockFns loaderFns)
    {
        var b = new StubBuilder();

        // Save state: flags, GPRs, then XSAVE for FPU/SSE/AVX. Reserve 0x40 = shadow + locals.
        b.Pushfq().Cld()
         .Push_AllGpr()
         .Mov_Rbp_Rsp()
         .And_Rsp_Align64()
         .Sub_Rsp_Imm32(4096)
         .ZeroXsaveHeader()
         .Xsave64()
         .Sub_Rsp(0x40);

        b.WriteDebugMarker(markerAddr, DEBUG_MARKER_ENTRY);

        // LdrLockLoaderLock(0, &state at [rsp+0x28], &cookie at [rsp+0x20])
        EmitLoaderLockAcquire(b, loaderFns.Lock);

        // Insert into PEB's three module lists (held under loader lock - atomic w.r.t. target's loader)
        EmitInsertIntoPebLists(b, ldrStructures);

        // TLS initialization via LdrpHandleTlsData(ldrEntry, BOOLEAN=1)
        var ldrEntry = (ulong)ldrStructures.Allocations.LdrEntry;
        if (ldrpHandleTlsData != 0 && ldrEntry != 0)
        {
            b.Mov_Reg_Imm64(1, ldrEntry)
             .Mov_Dl(1)
             .Mov_Reg_Imm64(0, ldrpHandleTlsData)
             .Call_Rax()
             .WriteTlsResultMarker(markerAddr);
        }

        if (callbacksAddr != 0)
            b.CallTlsCallbacks(callbacksAddr, moduleBase, markerAddr);

        b.WriteDebugMarker(markerAddr, DEBUG_MARKER_PRE_DLLMAIN);

        // DllMain(moduleBase, DLL_PROCESS_ATTACH, NULL) - mirrors how the loader normally calls it
        b.Mov_Reg_Imm64(1, moduleBase)
         .Mov_Edx_Imm32(1)
         .Xor_R8_R8()
         .Mov_Reg_Imm64(0, dllMain)
         .Call_Rax();

        b.WriteDebugMarker(markerAddr, DEBUG_MARKER_POST_DLLMAIN);

        // Unlink from all three PEB lists, then release loader lock — BEFORE the dotnetMain call.
        // NativeAOT's DllMain is a no-op; the runtime initializes lazily on the first UCO call,
        // and that init creates threads (finalizer, etc.) which need the loader lock to attach.
        // Calling dotnetMain under the loader lock is a guaranteed deadlock for NativeAOT shared
        // libs. Moving the dispatch out of the locked region makes it safe; for native DLLs that
        // don't need the loader released first, the swap is a no-op.
        EmitRemoveFromPebLists(b, ldrStructures);
        b.WriteDebugMarker(markerAddr, DEBUG_MARKER_POST_PEB_UNLINK);
        EmitLoaderLockRelease(b, loaderFns.Unlock);
        b.WriteDebugMarker(markerAddr, DEBUG_MARKER_POST_LOCK_RELEASE);

        if (dotnetMain != 0)
        {
            b.Mov_Reg_Imm64(0, dotnetMain).Call_Rax();
            b.WriteDebugMarker(markerAddr, DEBUG_MARKER_POST_DOTNETMAIN);
        }

        if (headerSize > 0)
            b.EraseMemory(moduleBase, headerSize);

        // Final sync sentinel - host polls this before cleaning up target-side allocations.
        // Must be written *before* state restoration since we need RAX/RCX free to do the store.
        b.WriteDebugMarker(markerAddr, SYNC_MARKER_DONE);

        // Restore state and return to original execution
        b.Add_Rsp(0x40)
         .Xrstor64()
         .Mov_Rsp_Rbp()
         .Pop_AllGpr()
         .Popfq();

        if (originalRip == 0)
            b.Ret();
        else
            b.Jmp_RipRelative(originalRip);  // RIP-relative jump preserves all registers

        return b.Build();
    }

    /// <summary>
    /// Emit <c>LdrLockLoaderLock(0, &amp;state, &amp;cookie)</c> with state at [rsp+0x28] and cookie at [rsp+0x20].
    /// </summary>
    private static void EmitLoaderLockAcquire(StubBuilder b, nint lockFn)
    {
        b.Xor_Ecx_Ecx()
         .Lea_Rdx_RspDisp8(0x28)
         .Lea_R8_RspDisp8(0x20)
         .Mov_Reg_Imm64(0, (ulong)lockFn)
         .Call_Rax();
    }

    /// <summary>
    /// Emit <c>LdrUnlockLoaderLock(0, cookie)</c> reading cookie from [rsp+0x20].
    /// </summary>
    private static void EmitLoaderLockRelease(StubBuilder b, nint unlockFn)
    {
        b.Xor_Ecx_Ecx()
         .Mov_Rdx_QwordPtr_RspDisp8(0x20)
         .Mov_Reg_Imm64(0, (ulong)unlockFn)
         .Call_Rax();
    }

    private static void EmitInsertIntoPebLists(StubBuilder b, LdrStructures s)
    {
        b.InsertTailList((ulong)s.InLoadOrderHead, (ulong)s.InLoadOrderEntryAddr)
         .InsertTailList((ulong)s.InMemoryOrderHead, (ulong)s.InMemoryOrderEntryAddr)
         .InsertTailList((ulong)s.InInitializationOrderHead, (ulong)s.InInitializationOrderEntryAddr);
    }

    private static void EmitRemoveFromPebLists(StubBuilder b, LdrStructures s)
    {
        b.RemoveEntryList((ulong)s.InLoadOrderEntryAddr)
         .RemoveEntryList((ulong)s.InMemoryOrderEntryAddr)
         .RemoveEntryList((ulong)s.InInitializationOrderEntryAddr);
    }

    #endregion

    #region CreateRemoteThread Wrapper

    /// <summary>
    /// Builds the CreateRemoteThread wrapper. Like the hijack stub it acquires the loader lock,
    /// inserts the LDR entry into the PEB lists, runs TLS init + callbacks + DllMain + DotnetMain,
    /// then removes the entry and releases the lock. Stack frame: 0x48 = 32 shadow + 16 locals
    /// (cookie at [rsp+0x20], state at [rsp+0x28]).
    /// </summary>
    private static (nint stubAddr, int stubLen, nint callbacksAddr, int callbacksLen) BuildDllMainWrapper(
        nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt,
        nint dotnetMainAddr, nint ldrpHandleTlsDataAddr,
        LdrStructures ldrStructures, LoaderLockFns loaderFns)
    {
        var dllMain = (ulong)(moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint);
        var callbacks = CollectTlsCallbacks(hProcess, moduleBase, nt);

        nint callbacksRemote = nint.Zero;
        int callbacksLen = 0;
        if (callbacks.Count > 0)
        {
            var cbBytes = callbacks.SelectMany(BitConverter.GetBytes).Concat(new byte[8]).ToArray();
            callbacksLen = cbBytes.Length;
            callbacksRemote = AllocateMemory(hProcess, (uint)callbacksLen, PAGE_READWRITE);
            WriteMemory(hProcess, callbacksRemote, cbBytes);
        }

        var b = new StubBuilder().Sub_Rsp(0x48);

        // Acquire loader lock (so PEB inserts + LdrpHandleTlsData + DllMain run as the loader expects)
        EmitLoaderLockAcquire(b, loaderFns.Lock);
        EmitInsertIntoPebLists(b, ldrStructures);

        // LdrpHandleTlsData initializes TLS for this thread
        var ldrEntry = (ulong)ldrStructures.Allocations.LdrEntry;
        if (ldrpHandleTlsDataAddr != nint.Zero && ldrEntry != 0)
        {
            b.Mov_Reg_Imm64(1, ldrEntry)
             .Mov_Dl(1)
             .Mov_Reg_Imm64(0, (ulong)ldrpHandleTlsDataAddr)
             .Call_Rax();
        }

        if (callbacksRemote != nint.Zero)
            b.CallTlsCallbacks((ulong)callbacksRemote, (ulong)moduleBase, debugMarker: 0);

        // DllMain(moduleBase, DLL_PROCESS_ATTACH, NULL)
        b.Mov_Reg_Imm64(1, (ulong)moduleBase)
         .Mov_Edx_Imm32(1)
         .Xor_R8_R8()
         .Mov_Reg_Imm64(0, dllMain)
         .Call_Rax();

        // PEB unlink + loader-lock release happen BEFORE dotnetMain — see notes on the hijack stub
        // for why (NativeAOT's lazy runtime init can deadlock under loader lock).
        EmitRemoveFromPebLists(b, ldrStructures);
        EmitLoaderLockRelease(b, loaderFns.Unlock);

        if (dotnetMainAddr != nint.Zero)
            b.Mov_Reg_Imm64(0, (ulong)dotnetMainAddr).Call_Rax();

        if (nt.OptionalHeader.SizeOfHeaders > 0)
            b.EraseMemory((ulong)moduleBase, nt.OptionalHeader.SizeOfHeaders);

        b.Add_Rsp(0x48).Ret();

        var stub = b.Build();
        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, remote, stub);
        ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, remote, (uint)stub.Length);
        return (remote, stub.Length, callbacksRemote, callbacksLen);
    }

    #endregion

    #region DLL Loading

    private static nint LoadLibraryRemote(nint hProcess, string dllName)
    {
        nint remoteStr = nint.Zero, remoteUnicode = nint.Zero, remoteHandle = nint.Zero, wrapper = nint.Zero;

        try
        {
            var wideBytes = System.Text.Encoding.Unicode.GetBytes(dllName + "\0");
            remoteStr = AllocateMemory(hProcess, (uint)wideBytes.Length, PAGE_READWRITE);
            WriteMemory(hProcess, remoteStr, wideBytes);

            var unicodeBuf = new byte[16];
            ushort len = (ushort)(wideBytes.Length - 2);
            BitConverter.GetBytes(len).CopyTo(unicodeBuf, 0);
            BitConverter.GetBytes((ushort)wideBytes.Length).CopyTo(unicodeBuf, 2);
            BitConverter.GetBytes((ulong)remoteStr).CopyTo(unicodeBuf, 8);

            remoteUnicode = AllocateMemory(hProcess, 16, PAGE_READWRITE);
            WriteMemory(hProcess, remoteUnicode, unicodeBuf);

            remoteHandle = AllocateMemory(hProcess, 8, PAGE_READWRITE);

            var ldrLoadDll = GetProcAddress(GetModuleHandle("ntdll.dll"), "LdrLoadDll");
            wrapper = BuildLdrLoadDllWrapper(hProcess, (ulong)ldrLoadDll, (ulong)remoteUnicode, (ulong)remoteHandle);

            CreateRemoteThreadAndWait(hProcess, wrapper, nint.Zero, wait: true);

            return (nint)BitConverter.ToInt64(ReadMemory(hProcess, remoteHandle, 8));
        }
        finally
        {
            if (wrapper != nint.Zero) try { FreeMemory(hProcess, wrapper); } catch { }
            if (remoteStr != nint.Zero) try { FreeMemory(hProcess, remoteStr); } catch { }
            if (remoteUnicode != nint.Zero) try { FreeMemory(hProcess, remoteUnicode); } catch { }
            if (remoteHandle != nint.Zero) try { FreeMemory(hProcess, remoteHandle); } catch { }
        }
    }

    private static nint BuildLdrLoadDllWrapper(nint hProcess, ulong ldrLoadDll, ulong unicodeStr, ulong handleOut)
    {
        var stub = new StubBuilder()
            .Sub_Rsp(0x28)
            .Mov_Reg_Imm64(1, 0)
            .Mov_Reg_Imm64(2, 0)
            .Mov_Reg_Imm64(8, unicodeStr)
            .Mov_Reg_Imm64(9, handleOut)
            .Mov_Reg_Imm64(10, ldrLoadDll)
            .Call_R10()
            .Add_Rsp(0x28)
            .Ret()
            .Build();

        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, remote, stub);
        ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, remote, (uint)stub.Length);
        return remote;
    }

    #endregion

    #region Utilities

    private static void ExecuteRemoteStub(nint hProcess, byte[] stub)
    {
        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        try
        {
            WriteMemory(hProcess, remote, stub);
            ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
            FlushInstructionCache(hProcess, remote, (uint)stub.Length);
            CreateRemoteThreadAndWait(hProcess, remote, nint.Zero, wait: true);
        }
        finally
        {
            FreeMemory(hProcess, remote);
        }
    }

    private static bool IsInSystemModule(ulong rip) =>
        _systemModuleRanges.Any(r => rip >= r.start && rip < r.start + r.size);

    private static readonly (ulong start, ulong size)[] _systemModuleRanges = InitSystemModuleRanges();

    private static (ulong, ulong)[] InitSystemModuleRanges()
    {
        string[] modules = ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "win32u.dll"];
        var ranges = new List<(ulong, ulong)>();
        var hCurrent = GetCurrentProcess();

        foreach (var name in modules)
        {
            var h = GetModuleHandle(name);
            if (h == nint.Zero) continue;

            if (GetModuleInformation(hCurrent, h, out var info, (uint)Marshal.SizeOf<MODULEINFO>()))
                ranges.Add(((ulong)h, info.SizeOfImage));
            else
                ranges.Add(((ulong)h, DEFAULT_MODULE_SIZE_FALLBACK));
        }

        return [.. ranges];
    }

    private static void WakeThread(uint tid, nint hThread)
    {
        PostThreadMessage(tid, 0, 0, nint.Zero);
        NtAlertThread(hThread);
    }

    #endregion

    #region Thread Helpers

    private readonly record struct ThreadInfo(uint Id, nint Handle)
    {
        public bool TryGetContext(out CONTEXT64 ctx)
        {
            ctx = default;
            if (SuspendThread(Handle) == 0xFFFFFFFF) return false;
            if (!TryGetThreadContext(Handle, out ctx))
            {
                ResumeThread(Handle);
                return false;
            }
            return true;
        }

        public bool TrySetContext(CONTEXT64 ctx)
        {
            if (!TrySetThreadContext(Handle, ctx))
            {
                ResumeThread(Handle);
                return false;
            }
            return true;
        }

        public void ResumeCompletely()
        {
            uint count;
            do { count = ResumeThread(Handle); } while (count > 0 && count != 0xFFFFFFFF);
        }

        public void Dispose()
        {
            ResumeCompletely();
            CloseHandleSafe(Handle);
        }
    }

    private sealed class ThreadSnapshot(int pid) : IDisposable
    {
        private readonly nint _handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        public IEnumerable<ThreadInfo> EnumerateThreads()
        {
            var entry = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            if (!Thread32First(_handle, ref entry)) yield break;

            do
            {
                if (entry.th32OwnerProcessID != (uint)pid) continue;
                var hThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
                if (hThread != nint.Zero)
                    yield return new ThreadInfo(entry.th32ThreadID, hThread);
            } while (Thread32Next(_handle, ref entry));
        }

        public void Dispose() => CloseHandleSafe(_handle);
    }

    #endregion

    #region Stub Builder

    /// <summary>
    /// Fluent x64 machine code builder for generating shellcode stubs.
    /// Provides type-safe methods for common x64 instructions used in injection stubs.
    /// </summary>
    private sealed class StubBuilder
    {
        private readonly List<byte> _code = [];

        /// <summary>Returns the assembled machine code.</summary>
        public byte[] Build() => [.. _code];

        /// <summary>Append raw bytes (e.g. a stolen prologue copied verbatim into a trampoline).</summary>
        public StubBuilder Raw(byte[] bytes) => Emit(bytes);

        private StubBuilder Emit(params byte[] bytes) { _code.AddRange(bytes); return this; }

        #region Stack Operations

        public StubBuilder Sub_Rsp(byte imm) => Emit(0x48, 0x83, 0xEC, imm);
        public StubBuilder Sub_Rsp_Imm32(uint imm) => Emit(0x48, 0x81, 0xEC).Emit(BitConverter.GetBytes(imm));
        public StubBuilder Add_Rsp(byte imm) => Emit(0x48, 0x83, 0xC4, imm);
        public StubBuilder Add_Rsp_Imm32(uint imm) => Emit(0x48, 0x81, 0xC4).Emit(BitConverter.GetBytes(imm));
        public StubBuilder Pushfq() => Emit(0x9C);
        public StubBuilder Popfq() => Emit(0x9D);
        public StubBuilder Cld() => Emit(0xFC);
        public StubBuilder Ret() => Emit(0xC3);

        #endregion

        #region GPR Save/Restore

        /// <summary>Pushes RAX, RCX, RDX, RBX, RBP, RSI, RDI, R8-R15.</summary>
        public StubBuilder Push_AllGpr() => Emit(0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57)
            .Emit(0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57);

        /// <summary>Pops R15-R8, RDI, RSI, RBP, RBX, RDX, RCX, RAX.</summary>
        public StubBuilder Pop_AllGpr() => Emit(0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58)
            .Emit(0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58);

        #endregion

        #region Extended State (XSAVE/FXSAVE)

        /// <summary>
        /// Saves x87/SSE/AVX/AVX-512 state using XSAVE64.
        /// Uses XGETBV to read XCR0 for the feature mask, ensuring all OS-enabled features are saved.
        /// Requires 64-byte aligned RSP and pre-zeroed header at [RSP+512].
        /// </summary>
        public StubBuilder Xsave64() =>
            Emit(0x31, 0xC9)                        // xor ecx, ecx
            .Emit(0x0F, 0x01, 0xD0)                 // xgetbv
            .Emit(0x48, 0x0F, 0xAE, 0x24, 0x24);    // xsave64 [rsp]

        /// <summary>
        /// Restores x87/SSE/AVX/AVX-512 state using XRSTOR64.
        /// Uses XGETBV to read XCR0 for the feature mask.
        /// </summary>
        public StubBuilder Xrstor64() =>
            Emit(0x31, 0xC9)                        // xor ecx, ecx
            .Emit(0x0F, 0x01, 0xD0)                 // xgetbv
            .Emit(0x48, 0x0F, 0xAE, 0x2C, 0x24);    // xrstor64 [rsp]

        /// <summary>Saves x87/SSE state only (no AVX). Requires 16-byte aligned RSP.</summary>
        public StubBuilder Fxsave64() => Emit(0x48, 0x0F, 0xAE, 0x04, 0x24);

        /// <summary>Restores x87/SSE state only (no AVX).</summary>
        public StubBuilder Fxrstor64() => Emit(0x48, 0x0F, 0xAE, 0x0C, 0x24);

        /// <summary>
        /// Zeros the XSAVE header at [RSP+512] (64 bytes).
        /// Must be called before XSAVE to prevent XRSTOR from reading garbage in XSTATE_BV.
        /// Clobbers RAX, RCX, RDI (restored by Pop_AllGpr).
        /// </summary>
        public StubBuilder ZeroXsaveHeader() =>
            Emit(0x48, 0x8D, 0xBC, 0x24, 0x00, 0x02, 0x00, 0x00)  // lea rdi, [rsp+512]
            .Emit(0x31, 0xC0)                                      // xor eax, eax
            .Emit(0xB9, 0x08, 0x00, 0x00, 0x00)                    // mov ecx, 8
            .Emit(0xF3, 0x48, 0xAB);                               // rep stosq

        #endregion

        #region Stack Frame

        public StubBuilder Mov_Rbp_Rsp() => Emit(0x48, 0x89, 0xE5);
        public StubBuilder Mov_Rsp_Rbp() => Emit(0x48, 0x89, 0xEC);
        public StubBuilder And_Rsp_Align16() => Emit(0x48, 0x83, 0xE4, 0xF0);
        public StubBuilder And_Rsp_Align64() => Emit(0x48, 0x83, 0xE4, 0xC0);

        #endregion

        #region Register Operations

        /// <summary>Moves 64-bit immediate to register (0=RAX, 1=RCX, ..., 8=R8, etc).</summary>
        public StubBuilder Mov_Reg_Imm64(byte reg, ulong imm)
        {
            byte prefix = reg < 8 ? (byte)0x48 : (byte)0x49;
            byte opcode = (byte)(0xB8 + (reg & 7));
            return Emit(prefix, opcode).Emit(BitConverter.GetBytes(imm));
        }

        public StubBuilder Mov_Edx_Imm32(uint imm) => Emit(0xBA).Emit(BitConverter.GetBytes(imm));
        public StubBuilder Mov_Dl(byte imm) => Emit(0xB2, imm);
        public StubBuilder Xor_R8_R8() => Emit(0x41, 0x31, 0xC0);
        public StubBuilder Xor_Ecx_Ecx() => Emit(0x31, 0xC9);
        public StubBuilder Cmp_Rcx_Rax() => Emit(0x48, 0x39, 0xC1);
        public StubBuilder Mov_Ptr_Rcx_Rdx() => Emit(0x48, 0x89, 0x11);

        /// <summary>lea rdx, [rsp + disp8] - load effective address of stack local into rdx.</summary>
        public StubBuilder Lea_Rdx_RspDisp8(byte disp) => Emit(0x48, 0x8D, 0x54, 0x24, disp);

        /// <summary>lea r8, [rsp + disp8] - load effective address of stack local into r8.</summary>
        public StubBuilder Lea_R8_RspDisp8(byte disp) => Emit(0x4C, 0x8D, 0x44, 0x24, disp);

        /// <summary>mov rdx, [rsp + disp8] - load qword from stack local into rdx.</summary>
        public StubBuilder Mov_Rdx_QwordPtr_RspDisp8(byte disp) => Emit(0x48, 0x8B, 0x54, 0x24, disp);

        #endregion

        #region Doubly-Linked List Operations

        /// <summary>
        /// Emits the equivalent of InsertTailList(listHead, entry):
        /// <code>
        ///   prevTail        = listHead.Blink
        ///   entry.Flink     = listHead
        ///   entry.Blink     = prevTail
        ///   prevTail.Flink  = entry
        ///   listHead.Blink  = entry
        /// </code>
        /// Clobbers RAX, RCX, RDX. Caller must hold the appropriate lock (loader lock for PEB lists).
        /// </summary>
        public StubBuilder InsertTailList(ulong listHead, ulong entry) =>
            Mov_Reg_Imm64(2, listHead)              // mov rdx, listHead
            .Mov_Reg_Imm64(1, entry)                // mov rcx, entry
            .Emit(0x48, 0x8B, 0x42, 0x08)           // mov rax, [rdx+8]   - prevTail = listHead.Blink
            .Emit(0x48, 0x89, 0x11)                 // mov [rcx], rdx     - entry.Flink = listHead
            .Emit(0x48, 0x89, 0x41, 0x08)           // mov [rcx+8], rax   - entry.Blink = prevTail
            .Emit(0x48, 0x89, 0x08)                 // mov [rax], rcx     - prevTail.Flink = entry
            .Emit(0x48, 0x89, 0x4A, 0x08);          // mov [rdx+8], rcx   - listHead.Blink = entry

        /// <summary>
        /// Emits the equivalent of RemoveEntryList(entry):
        /// <code>
        ///   flink = entry.Flink
        ///   blink = entry.Blink
        ///   blink.Flink = flink
        ///   flink.Blink = blink
        /// </code>
        /// Clobbers RAX, RCX, RDX. Caller must hold the appropriate lock.
        /// </summary>
        public StubBuilder RemoveEntryList(ulong entry) =>
            Mov_Reg_Imm64(1, entry)                 // mov rcx, entry
            .Emit(0x48, 0x8B, 0x01)                 // mov rax, [rcx]     - flink
            .Emit(0x48, 0x8B, 0x51, 0x08)           // mov rdx, [rcx+8]   - blink
            .Emit(0x48, 0x89, 0x02)                 // mov [rdx], rax     - blink.Flink = flink
            .Emit(0x48, 0x89, 0x50, 0x08);          // mov [rax+8], rdx   - flink.Blink = blink

        #endregion

        #region Control Flow

        public StubBuilder Call_Rax() => Emit(0xFF, 0xD0);
        public StubBuilder Call_R10() => Emit(0x41, 0xFF, 0xD2);
        public StubBuilder Jmp_Rax() => Emit(0xFF, 0xE0);
        public StubBuilder Jb(byte offset) => Emit(0x72, offset);
        public StubBuilder Jae(byte offset) => Emit(0x73, offset);

        /// <summary>
        /// RIP-relative indirect jump. Reads target address from inline data.
        /// Does not modify any registers - safe for use after restoring thread state.
        /// </summary>
        public StubBuilder Jmp_RipRelative(ulong targetAddr) =>
            Emit(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00)  // jmp qword ptr [rip+0]
            .Emit(BitConverter.GetBytes(targetAddr));

        public StubBuilder Jmp_Indirect(ulong addr) => Emit(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00).Emit(BitConverter.GetBytes(addr));

        #endregion

        #region Debug Markers

        /// <summary>Writes a 64-bit debug marker value to the specified address.</summary>
        public StubBuilder WriteDebugMarker(ulong markerAddr, ulong value) =>
            Mov_Reg_Imm64(0, markerAddr).Mov_Reg_Imm64(1, value).Emit(0x48, 0x89, 0x08);

        /// <summary>Writes LdrpHandleTlsData return value with 0x5555 prefix to debug marker.</summary>
        public StubBuilder WriteTlsResultMarker(ulong markerAddr) =>
            Mov_Reg_Imm64(1, markerAddr)
            .Emit(0x89, 0xC0)                                     // mov eax, eax
            .Emit(0x48, 0xC7, 0xC2, 0x55, 0x55, 0x00, 0x00)       // mov rdx, 0x5555
            .Emit(0x48, 0xC1, 0xE2, 0x20)                         // shl rdx, 32
            .Emit(0x48, 0x09, 0xC2)                               // or rdx, rax
            .Mov_Ptr_Rcx_Rdx();

        #endregion

        #region High-Level Operations

        /// <summary>Generates a loop that calls each TLS callback in a null-terminated array.</summary>
        public StubBuilder CallTlsCallbacks(ulong callbacksAddr, ulong moduleBase, ulong debugMarker)
        {
            Mov_Reg_Imm64(3, callbacksAddr);

            int loopStart = _code.Count;
            Emit(0x48, 0x8B, 0x03);  // mov rax, [rbx]
            Emit(0x48, 0x85, 0xC0);  // test rax, rax
            Emit(0x74);
            int jzPos = _code.Count; Emit(0x00);

            Mov_Reg_Imm64(1, moduleBase);
            Mov_Edx_Imm32(2);
            Xor_R8_R8();
            Call_Rax();

            Emit(0x48, 0x83, 0xC3, 0x08);
            int jumpBack = loopStart - (_code.Count + 2);
            Emit(0xEB, (byte)jumpBack);

            _code[jzPos] = (byte)(_code.Count - jzPos - 1);

            if (debugMarker != 0)
                WriteDebugMarker(debugMarker, DEBUG_MARKER_POST_TLS);

            return this;
        }

        /// <summary>Zeros memory at the specified address using rep stosb.</summary>
        public StubBuilder EraseMemory(ulong addr, uint size) =>
            Mov_Reg_Imm64(7, addr)
            .Emit(0xB9).Emit(BitConverter.GetBytes(size))
            .Emit(0x31, 0xC0)
            .Emit(0xF3, 0xAA);

        #endregion
    }

    #endregion
}
