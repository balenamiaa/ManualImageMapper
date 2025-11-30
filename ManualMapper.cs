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
    /// then resumes. More stealthy as no new thread is created.
    /// </summary>
    public sealed record ThreadHijacking(
        TimeSpan DebugMarkerCheckDelay,
        bool EnableDebugPrivilege = true,
        bool EnableDebugMarker = false,
        bool LogGeneratedStub = false) : InjectionMode;

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
    /// Injects a DLL into the target process using manual mapping.
    /// </summary>
    public static void Inject(byte[] dllBytes, int pid, InjectionMode mode)
    {
        var nt = GetNtHeaders(dllBytes);
        var sections = GetSectionHeaders(dllBytes);

        Log.Information("Opening target process {Pid}", pid);
        var hProcess = OpenTargetProcess(pid);
        nint remoteBase = nint.Zero;
        bool dllMainExecuted = false;

        try
        {
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
            var dllName = Path.GetFileName(
                Environment.GetCommandLineArgs().ElementAtOrDefault(1) ?? "injected.dll");

            // Link to PEB for CRT support; LdrpHandleTlsData will be called from the stub
            Log.Debug("Linking module to PEB");
            var (remoteLdrEntry, ldrpHandleTlsDataAddr) = InitializeCrtModulePebOnly(
                hProcess, pid, remoteBase, nt.OptionalHeader.SizeOfImage,
                dllEntryPoint, nt.OptionalHeader.ImageBase, dllName);

            if (remoteLdrEntry != nint.Zero)
                Log.Debug("PEB linked - LDR entry: 0x{Entry:X}", (ulong)remoteLdrEntry);

            // Patch NativeAOT's PalGetModuleHandleFromPointer to handle our unmapped module
            PatchNativeAotModuleLookup(hProcess, remoteBase, dllBytes, nt.OptionalHeader.SizeOfImage);

            FlushInstructionCache(hProcess, remoteBase, nt.OptionalHeader.SizeOfImage);

            var dotnetMainAddr = GetExportRva(dllBytes, "DotnetMain") is int rva and > 0
                ? remoteBase + rva
                : nint.Zero;

            dllMainExecuted = mode switch
            {
                InjectionMode.ThreadHijacking hijack => ExecuteViaThreadHijacking(
                    hProcess, pid, remoteBase, nt, hijack, dotnetMainAddr, ldrpHandleTlsDataAddr, remoteLdrEntry),

                InjectionMode.CreateRemoteThread crt => ExecuteViaRemoteThread(
                    hProcess, remoteBase, nt, crt, dotnetMainAddr, ldrpHandleTlsDataAddr, remoteLdrEntry),

                _ => throw new ArgumentException($"Unsupported injection mode: {mode.GetType().Name}")
            };

            Log.Debug("Unlinking module from PEB");
            UnlinkFromPEB(hProcess, remoteBase);
        }
        catch
        {
            if (!dllMainExecuted && remoteBase != nint.Zero)
            {
                Log.Debug("Freeing remote memory due to injection failure");
                try { FreeMemory(hProcess, remoteBase); } catch { }
            }
            throw;
        }
        finally
        {
            Log.Information("Injection complete");
            CloseHandleSafe(hProcess);
        }
    }

    private static bool ExecuteViaThreadHijacking(
        nint hProcess, int pid, nint remoteBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.ThreadHijacking config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr, nint remoteLdrEntry)
    {
        Log.Information("Using thread hijacking");

        var debugMarker = HijackFirstThread(
            pid, hProcess, remoteBase, nt, config, dotnetMainAddr, ldrpHandleTlsDataAddr, remoteLdrEntry);

        if (config.EnableDebugMarker)
        {
            if (debugMarker == nint.Zero)
            {
                Log.Warning("Failed to hijack thread");
                return false;
            }

            Thread.Sleep(config.DebugMarkerCheckDelay);
            LogDebugMarkerStatus(hProcess, debugMarker);
        }

        return true;
    }

    private static bool ExecuteViaRemoteThread(
        nint hProcess, nint remoteBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.CreateRemoteThread config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr, nint remoteLdrEntry)
    {
        Log.Information("Using CreateRemoteThread (timeout: {TimeoutMs}ms)", config.TimeoutMs);

        var dllMain = remoteBase + (int)nt.OptionalHeader.AddressOfEntryPoint;
        var wrapper = BuildDllMainWrapper(
            hProcess, (ulong)dllMain, (ulong)remoteBase, nt.OptionalHeader.SizeOfHeaders,
            (ulong)dotnetMainAddr, (ulong)ldrpHandleTlsDataAddr, (ulong)remoteLdrEntry);

        try
        {
            var hThread = CreateRemoteThreadAndWait(hProcess, wrapper, nint.Zero, wait: false);
            if (hThread != nint.Zero)
            {
                WaitForSingleObject(hThread, config.TimeoutMs);
                CloseHandleSafe(hThread);
                return true;
            }
            return false;
        }
        finally
        {
            FreeMemory(hProcess, wrapper);
        }
    }

    private static void LogDebugMarkerStatus(nint hProcess, nint debugMarker)
    {
        try
        {
            var value = BitConverter.ToUInt64(ReadMemory(hProcess, debugMarker, 8));

            var stage = (value >> 32) == 0x5555
                ? $"LdrpHandleTlsData returned 0x{value & 0xFFFFFFFF:X8}"
                : value switch
                {
                    DEBUG_MARKER_INITIAL => "INITIAL (stub never ran)",
                    DEBUG_MARKER_ENTRY => "ENTRY",
                    DEBUG_MARKER_POST_TLS => "POST_TLS",
                    DEBUG_MARKER_PRE_DLLMAIN => "PRE_DLLMAIN",
                    DEBUG_MARKER_POST_DLLMAIN => "POST_DLLMAIN",
                    0x6666666666666666 => "PRE_DOTNETMAIN",
                    DEBUG_MARKER_POST_DOTNETMAIN => "POST_DOTNETMAIN",
                    _ => $"UNKNOWN (0x{value:X})"
                };

            Log.Information("Debug marker: {Stage}", stage);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to read debug marker");
        }
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
    /// Hooks PalGetModuleHandleFromPointer to return our module base for pointers within our module.
    /// NativeAOT calls GetModuleHandleExW which fails for manually mapped modules.
    /// </summary>
    private static void PatchNativeAotModuleLookup(nint hProcess, nint remoteBase, byte[] dll, uint sizeOfImage)
    {
        byte[] pattern = [0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xD1, 0x4C, 0x8D, 0x44, 0x24, 0x38, 0xB9, 0x05, 0x00, 0x00, 0x00];

        int rva = FindPattern(dll, pattern);
        if (rva < 0) return;

        var funcAddr = remoteBase + rva;
        ulong moduleEnd = (ulong)remoteBase + sizeOfImage;

        // Hook: check if pointer is in our range, return moduleBase if yes, else call original
        var hook = new StubBuilder()
            .Mov_Reg_Imm64(0, (ulong)remoteBase)  // rax = moduleBase
            .Cmp_Rcx_Rax()                         // if (ptr < moduleBase)
            .Jb(23)                                //   goto original
            .Mov_Reg_Imm64(0, moduleEnd)          // rax = moduleEnd
            .Cmp_Rcx_Rax()                         // if (ptr >= moduleEnd)
            .Jae(11)                               //   goto original
            .Mov_Reg_Imm64(0, (ulong)remoteBase)  // return moduleBase
            .Ret()
            .Jmp_Indirect((ulong)funcAddr + 14)   // original: jmp to funcAddr+14
            .Build();

        var hookAddr = AllocateMemory(hProcess, (uint)hook.Length, PAGE_EXECUTE_READWRITE);
        WriteMemory(hProcess, hookAddr, hook);
        ProtectMemory(hProcess, hookAddr, (uint)hook.Length, PAGE_EXECUTE_READ);

        // Patch original function to jump to hook
        var patch = new byte[14];
        patch[0] = 0xFF; patch[1] = 0x25; // jmp [rip+0]
        BitConverter.GetBytes((ulong)hookAddr).CopyTo(patch, 6);

        var oldProtect = ProtectMemory(hProcess, funcAddr, 14, PAGE_EXECUTE_READWRITE);
        WriteMemory(hProcess, funcAddr, patch);
        ProtectMemory(hProcess, funcAddr, 14, oldProtect);
        FlushInstructionCache(hProcess, funcAddr, 14);
        FlushInstructionCache(hProcess, hookAddr, (nuint)hook.Length);

        Log.Information("Hooked PalGetModuleHandleFromPointer for range [0x{Start:X}, 0x{End:X})",
            (ulong)remoteBase, moduleEnd);
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

    private static nint HijackFirstThread(
        int pid, nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.ThreadHijacking config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr, nint ldrEntryAddr)
    {
        if (!IsProcess64Bit(hProcess))
        {
            Log.Warning("Target is 32-bit - thread hijacking requires x64");
            return nint.Zero;
        }

        if (config.EnableDebugPrivilege)
            EnableSeDebugPrivilege();

        using var snap = new ThreadSnapshot(pid);
        var (active, blocked) = FindCandidateThreads(snap);

        return (active, blocked) switch
        {
            ({ } t, _) => HijackThread(t, hProcess, moduleBase, nt, config, false, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrEntryAddr),
            (_, { } t) => HijackThread(t, hProcess, moduleBase, nt, config, true, dotnetMainAddr, ldrpHandleTlsDataAddr, ldrEntryAddr),
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

    private static nint HijackThread(
        ThreadInfo thread, nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt,
        InjectionMode.ThreadHijacking config, bool needsWakeup,
        nint dotnetMainAddr, nint ldrpHandleTlsDataAddr, nint ldrEntryAddr)
    {
        try
        {
            if (!thread.TryGetContext(out var ctx))
                throw new InvalidOperationException($"Failed to get context for thread {thread.Id}");

            var (stubAddr, debugMarker) = BuildAndWriteLoaderStub(
                hProcess, moduleBase, nt, (nint)ctx.Rip, config,
                dotnetMainAddr, ldrpHandleTlsDataAddr, ldrEntryAddr);

            ctx.Rip = (ulong)stubAddr;
            if (!thread.TrySetContext(ctx))
                throw new InvalidOperationException($"Failed to set context for thread {thread.Id}");

            thread.ResumeCompletely();
            if (needsWakeup) WakeThread(thread.Id, thread.Handle);

            Log.Debug("Hijacked thread {Tid}", thread.Id);
            return debugMarker;
        }
        finally
        {
            thread.Dispose();
        }
    }

    private static (nint stubAddr, nint debugMarker) BuildAndWriteLoaderStub(
        nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt, nint originalRip,
        InjectionMode.ThreadHijacking config, nint dotnetMainAddr, nint ldrpHandleTlsDataAddr, nint ldrEntryAddr)
    {
        var dllMain = moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint;
        var callbacks = CollectTlsCallbacks(hProcess, moduleBase, nt);

        var callbacksRemote = nint.Zero;
        if (callbacks.Count > 0)
        {
            var cbBytes = callbacks.SelectMany(BitConverter.GetBytes).Concat(new byte[8]).ToArray();
            callbacksRemote = AllocateMemory(hProcess, (uint)cbBytes.Length, PAGE_READWRITE);
            WriteMemory(hProcess, callbacksRemote, cbBytes);
        }

        nint debugMarker = nint.Zero;
        if (config.EnableDebugMarker)
        {
            debugMarker = AllocateMemory(hProcess, 8, PAGE_READWRITE);
            WriteMemory(hProcess, debugMarker, BitConverter.GetBytes(DEBUG_MARKER_INITIAL));
        }

        var stub = BuildHijackStub(
            (ulong)moduleBase, (ulong)dllMain, (ulong)callbacksRemote, (ulong)originalRip,
            (ulong)debugMarker, nt.OptionalHeader.SizeOfHeaders,
            (ulong)dotnetMainAddr, (ulong)ldrpHandleTlsDataAddr, (ulong)ldrEntryAddr);

        if (config.LogGeneratedStub)
            Log.Information("Stub bytes: {Hex}", Convert.ToHexString(stub));

        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, remote, stub);
        ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, remote, (uint)stub.Length);

        return (remote, debugMarker);
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
    /// 1. Saves complete CPU state (GPRs, flags, x87/SSE/AVX via XSAVE)
    /// 2. Initializes TLS via LdrpHandleTlsData
    /// 3. Calls TLS callbacks and DllMain
    /// 4. Optionally calls DotnetMain export
    /// 5. Erases PE headers for stealth
    /// 6. Restores CPU state and jumps back to original RIP
    /// </summary>
    private static byte[] BuildHijackStub(
        ulong moduleBase, ulong dllMain, ulong callbacksAddr, ulong originalRip,
        ulong debugMarker, uint headerSize, ulong dotnetMain, ulong ldrpHandleTlsData, ulong ldrEntry)
    {
        var b = new StubBuilder();

        // Save state: flags, GPRs, then XSAVE for FPU/SSE/AVX
        b.Pushfq().Cld()
         .Push_AllGpr()
         .Mov_Rbp_Rsp()
         .And_Rsp_Align64()
         .Sub_Rsp_Imm32(4096)
         .ZeroXsaveHeader()
         .Xsave64()
         .Sub_Rsp(0x20);

        if (debugMarker != 0)
            b.WriteDebugMarker(debugMarker, DEBUG_MARKER_ENTRY);

        // TLS initialization via LdrpHandleTlsData
        if (ldrpHandleTlsData != 0 && ldrEntry != 0)
        {
            b.Mov_Reg_Imm64(1, ldrEntry)
             .Mov_Dl(1)
             .Mov_Reg_Imm64(0, ldrpHandleTlsData)
             .Call_Rax();

            if (debugMarker != 0)
                b.WriteTlsResultMarker(debugMarker);
        }

        if (callbacksAddr != 0)
            b.CallTlsCallbacks(callbacksAddr, moduleBase, debugMarker);

        if (debugMarker != 0)
            b.WriteDebugMarker(debugMarker, DEBUG_MARKER_PRE_DLLMAIN);

        // DllMain(moduleBase, DLL_PROCESS_ATTACH, NULL)
        b.Mov_Reg_Imm64(1, moduleBase)
         .Mov_Edx_Imm32(1)
         .Xor_R8_R8()
         .Mov_Reg_Imm64(0, dllMain)
         .Call_Rax();

        if (debugMarker != 0)
            b.WriteDebugMarker(debugMarker, DEBUG_MARKER_POST_DLLMAIN);

        if (dotnetMain != 0)
        {
            if (debugMarker != 0)
                b.WriteDebugMarker(debugMarker, 0x6666666666666666);

            b.Mov_Reg_Imm64(0, dotnetMain).Call_Rax();

            if (debugMarker != 0)
                b.WriteDebugMarker(debugMarker, DEBUG_MARKER_POST_DOTNETMAIN);
        }

        if (headerSize > 0)
            b.EraseMemory(moduleBase, headerSize);

        // Restore state and return to original execution
        b.Add_Rsp(0x20)
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

    #endregion

    #region CreateRemoteThread Wrapper

    private static nint BuildDllMainWrapper(
        nint hProcess, ulong dllMain, ulong moduleBase, uint headerSize,
        ulong dotnetMain, ulong ldrpHandleTlsData, ulong ldrEntry)
    {
        var b = new StubBuilder().Sub_Rsp(0x28);

        // Call LdrpHandleTlsData first
        if (ldrpHandleTlsData != 0 && ldrEntry != 0)
        {
            b.Mov_Reg_Imm64(1, ldrEntry)
             .Mov_Dl(1)
             .Mov_Reg_Imm64(0, ldrpHandleTlsData)
             .Call_Rax();
        }

        // Call DllMain
        b.Mov_Reg_Imm64(1, moduleBase)
         .Mov_Edx_Imm32(1)
         .Xor_R8_R8()
         .Mov_Reg_Imm64(0, dllMain)
         .Call_Rax();

        // Call DotnetMain if provided
        if (dotnetMain != 0)
            b.Mov_Reg_Imm64(0, dotnetMain).Call_Rax();

        // Erase headers
        if (headerSize > 0)
            b.EraseMemory(moduleBase, headerSize);

        b.Add_Rsp(0x28).Ret();

        var stub = b.Build();
        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, remote, stub);
        ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, remote, (uint)stub.Length);
        return remote;
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
        public StubBuilder Cmp_Rcx_Rax() => Emit(0x48, 0x39, 0xC1);
        public StubBuilder Mov_Ptr_Rcx_Rdx() => Emit(0x48, 0x89, 0x11);

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
