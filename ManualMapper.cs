// =============================================================================
// ManualMapper.cs - Manual PE Image Mapping for x64 Windows
// =============================================================================
//
// WHAT IS MANUAL MAPPING?
// -----------------------
// Manual mapping is a technique to load DLLs into a remote process without
// using standard Windows loader APIs (LoadLibrary). Instead, we perform all
// the loader's duties ourselves: parsing PE headers, allocating memory,
// copying sections, resolving imports, applying relocations, and calling
// the DLL's entry point.
//
// WHY USE MANUAL MAPPING?
// - Bypass DLL injection detection (no LdrLoadDll calls from our process)
// - Load DLLs that Windows refuses to load (invalid signatures, etc.)
// - Greater control over the loading process
// - Research and educational purposes
//
// INJECTION FLOW OVERVIEW:
// ------------------------
// 1. Parse PE headers (DOS, NT, Sections)
// 2. Allocate memory in target process (SizeOfImage bytes, RWX initially)
// 3. Copy PE headers to remote memory
// 4. Map each section to its virtual address
// 5. Apply relocations (patch absolute addresses for new base)
// 6. Resolve imports:
//    - Find each imported DLL in target process
//    - For each function, get its address from the DLL's export table
//    - Write function pointers to the Import Address Table (IAT)
//    - CRITICAL: Handle FORWARDED EXPORTS (see below)
// 7. Resolve delay-load imports (same as regular imports)
// 8. Register exception handlers (RtlAddFunctionTable for SEH/.NET)
// 9. Initialize CRT support:
//    - Link module to PEB loader lists
//    - Call LdrpHandleTlsData for Thread Local Storage
// 10. Set final section protections (RWX -> appropriate RX/RW/R)
// 11. Execute DllMain via CreateRemoteThread or thread hijacking
// 12. Unlink from PEB for stealth (optional)
//
// KEY BUGS WE FIXED:
// ------------------
//
// 1. FORWARDED EXPORTS BUG (kernel32!InitializeSListHead crash)
//    ------------------------------------------------------------
//    SYMPTOM: Crash when CRT DLL called kernel32!InitializeSListHead.
//             Debugger showed ASCII text being executed as machine code:
//               push rsp             ; 0x54 = 'T'
//               imul esi, "lize"     ; ASCII "NTDLL.Rt" being executed!
//
//    ROOT CAUSE: kernel32!InitializeSListHead is a FORWARDED EXPORT.
//    It doesn't contain code - it redirects to ntdll!RtlInitializeSListHead.
//    In the export table, a forwarded export's RVA points to a string like
//    "NTDLL.RtlInitializeSListHead" within the export directory itself.
//
//    Our old code didn't detect forwarders. It returned the address of
//    the forwarder STRING, and when the caller "called" this "function",
//    it executed ASCII text as machine code!
//
//    FIX: In ExportResolver.cs, we now check if the export RVA falls
//    within the export directory (between VirtualAddress and VirtualAddress
//    + Size). If so, we parse the forwarder string and recursively resolve
//    from the target DLL.
//
// 2. LDRPHANDLETLSDATA WIN11 25H2+ BUG
//    ---------------------------------
//    SYMPTOM: LdrpHandleTlsData returned success but TLS didn't work.
//
//    ROOT CAUSE: Windows 11 25H2 changed LdrpHandleTlsData from 1 to 2
//    parameters. The second parameter (BOOLEAN) must be TRUE.
//
//    FIX: In PatternScanner.cs, we updated the stub to always pass
//    dl=1 (TRUE) as the second parameter. This is safely ignored on
//    older Windows versions that only take 1 parameter.
//
// MODULE ORGANIZATION:
// --------------------
// The codebase is split into focused modules under Interop/:
//
//   NativeMethods.cs  - P/Invoke declarations for Windows APIs
//   Structures.cs     - PE format and Windows data structures
//   Constants.cs      - All constants (memory, PE, PEB offsets)
//   Helpers.cs        - Memory, process, module, thread utilities
//   ExportResolver.cs - Export table parsing with forwarder support
//   PatternScanner.cs - Finding internal functions by byte patterns
//   PebLinker.cs      - PEB linking for CRT/TLS support
//   Win32.cs          - Unified facade re-exporting all modules
//
// ADDING SUPPORT FOR NEW WINDOWS VERSIONS:
// ----------------------------------------
// 1. Check if LdrpHandleTlsData pattern still works (PatternScanner.cs)
//    - Use IDA/Ghidra to find new function prologue if needed
// 2. Check if PEB offsets changed (Constants.cs)
// 3. Check if structure layouts changed (Structures.cs)
// 4. Test both CreateRemoteThread and thread hijacking modes
//
// TESTING:
// --------
// Compile a test DLL (we use a Rust DLL with user32!MessageBoxW):
//   dotnet run a.dll Notepad thread   # Thread hijacking mode
//   dotnet run a.dll Notepad remote   # CreateRemoteThread mode
//
// If MessageBox appears in Notepad, injection succeeded!
//
// =============================================================================

using System.Runtime.InteropServices;
using Serilog;

using ManualImageMapper.Interop;
using static ManualImageMapper.Interop.Win32;
using static ManualImageMapper.Interop.Win32.Const;
using static ManualImageMapper.Interop.Structures;

namespace ManualImageMapper;

/// <summary>
/// Injection mode configuration. Choose between CreateRemoteThread (simpler, more detectable)
/// or ThreadHijacking (stealthier, redirects existing thread to our code).
/// </summary>
public abstract record InjectionMode
{
    /// <summary>
    /// Thread hijacking mode: suspends an existing thread in the target process,
    /// modifies its instruction pointer (RIP) to point to our loader stub,
    /// then resumes the thread. More stealthy as no new thread is created.
    /// <para>
    /// The stub saves all registers, calls DllMain with DLL_PROCESS_ATTACH,
    /// restores registers, and jumps back to the original RIP.
    /// </para>
    /// </summary>
    /// <param name="DebugMarkerCheckDelay">Time to wait before checking debug marker value.</param>
    /// <param name="EnableDebugPrivilege">Enable SeDebugPrivilege for accessing protected processes.</param>
    /// <param name="EnableDebugMarker">Allocate a debug marker to track stub execution progress.</param>
    /// <param name="LogGeneratedStub">Log the generated stub bytes for debugging.</param>
    public sealed record ThreadHijacking(
        TimeSpan DebugMarkerCheckDelay,
        bool EnableDebugPrivilege = true,
        bool EnableDebugMarker = false,
        bool LogGeneratedStub = false) : InjectionMode;

    /// <summary>
    /// CreateRemoteThread mode: creates a new thread in the target process
    /// that executes our loader stub. Simpler but more detectable.
    /// </summary>
    /// <param name="TimeoutMs">Timeout in milliseconds waiting for DllMain to complete.</param>
    public sealed record CreateRemoteThread(uint TimeoutMs = 30_000) : InjectionMode;
}

/// <summary>
/// Manual PE image mapper that injects DLLs into remote processes without using
/// Windows loader APIs (LoadLibrary/LdrLoadDll). Performs all loader duties manually:
/// memory allocation, section mapping, relocation, import resolution, and DllMain execution.
/// <para>
/// <b>SUPPORTED FEATURES:</b>
/// <list type="bullet">
/// <item>x64 PE images only (IMAGE_FILE_MACHINE_AMD64)</item>
/// <item>Import resolution including ordinal imports</item>
/// <item>Forwarded export resolution (e.g., kernel32→ntdll)</item>
/// <item>Delay-load import resolution</item>
/// <item>Exception handler registration (SEH, .NET AOT)</item>
/// <item>CRT/TLS support via PEB linking and LdrpHandleTlsData</item>
/// <item>Thread hijacking or CreateRemoteThread execution</item>
/// <item>PEB unlinking for basic stealth</item>
/// </list>
/// </para>
/// </summary>
public static partial class ManualMapper
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(ManualMapper));

    /// <summary>
    /// Performs complete manual mapping of a DLL into a target process and executes DllMain.
    /// <para>
    /// <b>INJECTION STEPS:</b>
    /// <list type="number">
    /// <item>Parse PE headers to get image size, entry point, sections</item>
    /// <item>Allocate SizeOfImage bytes in target with PAGE_READWRITE</item>
    /// <item>Copy PE headers and map each section to its virtual address</item>
    /// <item>Apply relocations (patch absolute addresses for the new base)</item>
    /// <item>Resolve imports - for each imported function:
    ///   <list type="bullet">
    ///   <item>Find the DLL in target process (or load via LdrLoadDll)</item>
    ///   <item>Parse the DLL's export table to find the function</item>
    ///   <item>Handle forwarded exports by following the chain</item>
    ///   <item>Write function pointer to the Import Address Table</item>
    ///   </list>
    /// </item>
    /// <item>Resolve delay-load imports (same process, different PE directory)</item>
    /// <item>Register exception handlers via RtlAddFunctionTable</item>
    /// <item>Initialize CRT support: link to PEB, call LdrpHandleTlsData</item>
    /// <item>Set final section protections (R, RW, RX per section flags)</item>
    /// <item>Execute DllMain with DLL_PROCESS_ATTACH</item>
    /// <item>Unlink from PEB for basic stealth</item>
    /// </list>
    /// </para>
    /// </summary>
    /// <param name="dllBytes">The raw DLL file bytes to inject.</param>
    /// <param name="pid">Process ID of the target process.</param>
    /// <param name="mode">Injection mode (ThreadHijacking or CreateRemoteThread).</param>
    /// <exception cref="InvalidOperationException">If PE parsing fails or image is unsupported.</exception>
    /// <exception cref="System.ComponentModel.Win32Exception">If Windows API calls fail.</exception>
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
            ResolveImports(hProcess, remoteBase, dllBytes, nt, sections, pid, mode);

            Log.Debug("Resolving delay-load imports");
            ResolveDelayLoadImports(hProcess, remoteBase, dllBytes, nt, sections, pid, mode);

            // Register exception handlers for .NET AOT DLLs
            RegisterExceptionHandlers(hProcess, remoteBase, dllBytes, nt, sections);

            Log.Debug("Setting final section protections");
            SetSectionProtections(hProcess, remoteBase, sections);

            // Initialize CRT support BEFORE erasing headers!
            // LdrpHandleTlsData needs to read the TLS directory from PE headers.
            var dllEntryPoint = remoteBase + (int)nt.OptionalHeader.AddressOfEntryPoint;
            string dllName = Path.GetFileName(Environment.GetCommandLineArgs().Length > 1
                ? Environment.GetCommandLineArgs()[1]
                : "injected.dll");

            Log.Debug("Initializing CRT support for {DllName}", dllName);
            var remoteLdrEntry = InitializeCrtModule(
                hProcess,
                pid,
                remoteBase,
                nt.OptionalHeader.SizeOfImage,
                dllEntryPoint,
                nt.OptionalHeader.ImageBase,
                dllName);

            if (remoteLdrEntry != nint.Zero)
            {
                Log.Information("CRT initialization complete - module linked to PEB at 0x{LdrEntry:X}", (ulong)remoteLdrEntry);
            }
            else
            {
                Log.Warning("CRT initialization failed - CRT DLLs may not work correctly");
            }

            // Now safe to erase headers after TLS is initialized
            Log.Debug("Flushing instruction cache & erasing headers");
            FlushInstructionCache(hProcess, remoteBase, nt.OptionalHeader.SizeOfImage);
            EraseHeaders(hProcess, remoteBase, nt.OptionalHeader.SizeOfHeaders);

            switch (mode)
            {
                case InjectionMode.ThreadHijacking hijack:
                    Log.Information("Hijacking thread to execute DllMain (debug privilege: {EnableDebug}, debug marker: {EnableMarker}, log stub: {LogStub})",
                        hijack.EnableDebugPrivilege, hijack.EnableDebugMarker, hijack.LogGeneratedStub);
                    var debugMarker = HijackFirstThread(pid, hProcess, remoteBase, nt, hijack);
                    dllMainExecuted = true; // Thread hijacking initiates DllMain execution

                    if (hijack.EnableDebugMarker && debugMarker == nint.Zero)
                    {
                        Log.Warning("Failed to hijack any thread (debug marker missing). Stopping injection.");
                        return;
                    }

                    if (hijack.EnableDebugMarker)
                    {
                        Thread.Sleep(hijack.DebugMarkerCheckDelay);
                        try
                        {
                            var markerValue = ReadMemory(hProcess, debugMarker, 8);
                            var value = BitConverter.ToUInt64(markerValue);
                            Log.Debug("Debug marker result: 0x{Value:X} (entry=0x{Entry:X}, preDllMain=0x{Pre:X}, postDllMain=0x{Post:X})",
                            value, DEBUG_MARKER_ENTRY, DEBUG_MARKER_PRE_DLLMAIN, DEBUG_MARKER_POST_DLLMAIN);
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
                    try
                    {
                        var hThread = CreateRemoteThreadAndWait(hProcess, wrapperStub, nint.Zero, wait: false);
                        Log.Debug("Created thread 0x{Thread:X} for wrapper", (ulong)hThread);
                        if (hThread != nint.Zero)
                        {
                            dllMainExecuted = true;
                            WaitForSingleObject(hThread, remoteThread.TimeoutMs);
                            CloseHandleSafe(hThread);
                        }
                    }
                    finally
                    {
                        // Free the wrapper stub after execution
                        FreeMemory(hProcess, wrapperStub);
                    }
                    break;

                default:
                    throw new ArgumentException($"Unsupported injection mode: {mode.GetType().Name}");
            }

            Log.Debug("Unlinking module from PEB");
            UnlinkFromPEB(hProcess, remoteBase);
        }
        catch
        {
            // If DllMain was never executed, we can safely free the allocated memory
            if (!dllMainExecuted && remoteBase != nint.Zero)
            {
                Log.Debug("Freeing remote memory due to injection failure (DllMain not executed)");
                try { FreeMemory(hProcess, remoteBase); } catch { /* ignore cleanup errors */ }
            }
            throw;
        }
        finally
        {
            Log.Information("Finished injecting - closing handle");
            CloseHandleSafe(hProcess);
        }
    }

    /// <summary>
    /// Applies PE relocations to patch absolute addresses for the new base address.
    /// </summary>
    private static void ApplyRelocations(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        var relocDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.BASERELOC];
        if (relocDir.Size == 0) return;

        var delta = remoteBase.ToInt64() - (long)nt.OptionalHeader.ImageBase;
        var localArr = localImage.ToArray();

        Log.Debug("Relocation directory size {Size} at RVA 0x{Rva:X}", relocDir.Size, relocDir.VirtualAddress);

        int processed = 0;
        int relocBaseOffset = RvaToOffset(relocDir.VirtualAddress, sections, localArr.Length);

        while (processed < relocDir.Size)
        {
            int blockOffset = relocBaseOffset + processed;
            var reloc = BytesToStructure<IMAGE_BASE_RELOCATION>(localArr, blockOffset);
            processed += Marshal.SizeOf<IMAGE_BASE_RELOCATION>();

            int entryCount = ((int)reloc.SizeOfBlock - Marshal.SizeOf<IMAGE_BASE_RELOCATION>()) / 2;
            Log.Debug("Reloc block VA 0x{BlockVa:X} entries {Count}", reloc.VirtualAddress, entryCount);

            for (int i = 0; i < entryCount; i++)
            {
                ushort entryVal = BitConverter.ToUInt16(localArr, relocBaseOffset + processed + i * 2);
                int type = entryVal >> 12;
                int offset = entryVal & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64)
                {
                    var patchAddrRemote = remoteBase + (int)reloc.VirtualAddress + offset;
                    var origBytes = ReadMemory(hProcess, patchAddrRemote, 8);
                    ulong origPtr = BitConverter.ToUInt64(origBytes);
                    ulong newPtr = origPtr + (ulong)delta;
                    WriteMemory(hProcess, patchAddrRemote, BitConverter.GetBytes(newPtr));
                    Log.Verbose("Patched 0x{PatchAddr:X}: {OrigPtr:X} -> {NewPtr:X}", (ulong)patchAddrRemote, origPtr, newPtr);
                }
            }
            processed += entryCount * 2;
        }
    }

    /// <summary>
    /// Resolves DLL imports by writing function pointers into the Import Address Table (IAT).
    /// <para>
    /// <b>IMPORT RESOLUTION PROCESS:</b>
    /// For each import descriptor (each imported DLL):
    /// <list type="number">
    /// <item>Find or load the DLL in the target process</item>
    /// <item>For each imported function (from OriginalFirstThunk/INT):
    ///   <list type="bullet">
    ///   <item>If ordinal import: resolve by ordinal number</item>
    ///   <item>If named import: resolve by function name from export table</item>
    ///   </list>
    /// </item>
    /// <item>Write resolved function pointer to FirstThunk/IAT</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>CRITICAL: FORWARDED EXPORT HANDLING</b><br/>
    /// Many exports don't contain code - they forward to another DLL.
    /// Example: kernel32!InitializeSListHead → ntdll!RtlInitializeSListHead<br/>
    /// <br/>
    /// The export table entry for a forwarder points to a string like
    /// "NTDLL.RtlInitializeSListHead" instead of code. We detect this by
    /// checking if the RVA falls within the export directory bounds.
    /// If so, we parse the forwarder string and recursively resolve from
    /// the target DLL. See <see cref="ExportResolver"/> for details.
    /// </para>
    /// </summary>
    private static void ResolveImports(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections, int pid, InjectionMode mode)
    {
        var importDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.IMPORT];
        if (importDir.Size == 0) return;

        int descriptorSize = Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
        int index = 0;
        var localArr = localImage.ToArray();

        Log.Debug("Processing import directory (size {Size}) at RVA 0x{Rva:X}", importDir.Size, importDir.VirtualAddress);

        while (true)
        {
            int descOffset = RvaToOffset(importDir.VirtualAddress + (uint)(index * descriptorSize), sections, localArr.Length);
            var desc = BytesToStructure<IMAGE_IMPORT_DESCRIPTOR>(localArr, descOffset);
            if (desc.Name == 0) break;

            string dllName = ReadAnsiString(localArr, desc.Name, sections);
            Log.Debug("Import descriptor {Dll}", dllName);

            var hModule = GetRemoteModuleHandle(hProcess, pid, dllName);
            if (hModule == nint.Zero)
            {
                // DLL not found by name - load it and use the returned handle directly
                // This is critical for API Set DLLs (api-ms-win-*) which resolve to real DLLs
                Log.Debug("{Dll} not loaded - loading via LdrLoadDll with CreateRemoteThread", dllName);
                hModule = LoadLibraryViaRemoteThread(hProcess, dllName);

                if (hModule == nint.Zero)
                {
                    Log.Warning("Failed to load {Dll} - import resolution will fail", dllName);
                }
            }

            int thunkIdx = 0;
            while (true)
            {
                uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
                int thunkOffset = RvaToOffset(thunkRva + (uint)(thunkIdx * 8), sections, localArr.Length);
                ulong importRef = BitConverter.ToUInt64(localArr, thunkOffset);
                if (importRef == 0) break;

                nint funcPtr;
                string identifier;

                if ((importRef & IMAGE_ORDINAL_FLAG64) != 0)
                {
                    ushort ordinal = (ushort)(importRef & 0xFFFF);
                    // For ordinal imports, we need to resolve from remote export table
                    funcPtr = GetRemoteProcAddressByOrdinal(hProcess, hModule, ordinal);
                    identifier = $"ordinal #{ordinal}";
                }
                else
                {
                    uint nameRva = (uint)(importRef & IMAGE_THUNK_RVA_MASK64);
                    string funcName = ReadAnsiString(localArr, nameRva + 2, sections);
                    funcPtr = GetRemoteProcAddress(hProcess, hModule, funcName, pid);
                    identifier = funcName;
                }

                if (funcPtr == nint.Zero)
                {
                    Log.Warning("Failed to resolve {Dll}!{Ident} - function pointer is null", dllName, identifier);
                }

                var iatEntryRemote = remoteBase + (int)desc.FirstThunk + thunkIdx * sizeof(ulong);
                WriteMemory(hProcess, iatEntryRemote, BitConverter.GetBytes((ulong)funcPtr));
                Log.Verbose("Resolved {Dll}!{Ident} -> 0x{Ptr:X}", dllName, identifier, (ulong)funcPtr);
                thunkIdx++;
            }
            index++;
        }
    }

    /// <summary>
    /// Resolves delay-loaded DLL imports by writing function pointers into the Delay IAT.
    /// Delay-loaded imports are normally resolved on first use, but for manual mapping
    /// we resolve them upfront for compatibility (especially with .NET AOT DLLs).
    /// </summary>
    private static void ResolveDelayLoadImports(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections, int pid, InjectionMode mode)
    {
        var delayDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.DELAY_IMPORT];
        if (delayDir.Size == 0) return;

        int descriptorSize = Marshal.SizeOf<IMAGE_DELAYLOAD_DESCRIPTOR>();
        int index = 0;
        var localArr = localImage.ToArray();

        Log.Debug("Processing delay-load directory (size {Size}) at RVA 0x{Rva:X}", delayDir.Size, delayDir.VirtualAddress);

        while (true)
        {
            int descOffset = RvaToOffset(delayDir.VirtualAddress + (uint)(index * descriptorSize), sections, localArr.Length);
            var desc = BytesToStructure<IMAGE_DELAYLOAD_DESCRIPTOR>(localArr, descOffset);
            if (desc.DllNameRVA == 0) break;

            string dllName = ReadAnsiString(localArr, desc.DllNameRVA, sections);
            Log.Debug("Delay-load descriptor {Dll}", dllName);

            // Ensure the DLL is loaded in the remote process
            var hModule = GetRemoteModuleHandle(hProcess, pid, dllName);
            if (hModule == nint.Zero)
            {
                // DLL not found by name - load it and use the returned handle directly
                // This is critical for API Set DLLs (api-ms-win-*) which resolve to real DLLs
                Log.Debug("Delay-load: {Dll} not loaded - loading via CreateRemoteThread", dllName);
                hModule = LoadLibraryViaRemoteThread(hProcess, dllName);

                if (hModule == nint.Zero)
                {
                    Log.Warning("Delay-load: Failed to load {Dll} - resolution will fail", dllName);
                }
            }

            // Write the module handle to the module handle storage (if specified)
            if (desc.ModuleHandleRVA != 0)
            {
                var remoteModuleHandleAddr = remoteBase + (int)desc.ModuleHandleRVA;
                WriteMemory(hProcess, remoteModuleHandleAddr, BitConverter.GetBytes((ulong)hModule));
            }

            // Resolve each import in the delay IAT
            int thunkIdx = 0;
            while (true)
            {
                // Read from INT (Import Name Table) to get import reference
                int intOffset = RvaToOffset(desc.ImportNameTableRVA + (uint)(thunkIdx * 8), sections, localArr.Length);
                ulong importRef = BitConverter.ToUInt64(localArr, intOffset);
                if (importRef == 0) break;

                nint funcPtr;
                string identifier;

                if ((importRef & IMAGE_ORDINAL_FLAG64) != 0)
                {
                    ushort ordinal = (ushort)(importRef & 0xFFFF);
                    funcPtr = GetRemoteProcAddressByOrdinal(hProcess, hModule, ordinal);
                    identifier = $"ordinal #{ordinal}";
                }
                else
                {
                    uint nameRva = (uint)(importRef & IMAGE_THUNK_RVA_MASK64);
                    string funcName = ReadAnsiString(localArr, nameRva + 2, sections);
                    funcPtr = GetRemoteProcAddress(hProcess, hModule, funcName, pid);
                    identifier = funcName;
                }

                if (funcPtr == nint.Zero)
                {
                    Log.Warning("Delay-load: Failed to resolve {Dll}!{Ident} - function pointer is null", dllName, identifier);
                }

                // Write to Delay IAT
                var iatEntryRemote = remoteBase + (int)desc.ImportAddressTableRVA + thunkIdx * sizeof(ulong);
                WriteMemory(hProcess, iatEntryRemote, BitConverter.GetBytes((ulong)funcPtr));
                Log.Verbose("Delay-load resolved {Dll}!{Ident} -> 0x{Ptr:X}", dllName, identifier, (ulong)funcPtr);
                thunkIdx++;
            }
            index++;
        }
    }

    /// <summary>
    /// Reads a null-terminated ANSI string from the PE image at the specified RVA.
    /// </summary>
    private static string ReadAnsiString(byte[] image, uint rva, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        int offset = RvaToOffset(rva, sections, image.Length);
        if (offset < 0 || offset >= image.Length)
            throw new InvalidOperationException($"Invalid RVA 0x{rva:X} - offset {offset} is outside image bounds (size: {image.Length})");

        int len = 0;
        int maxLen = image.Length - offset;
        while (len < maxLen && image[offset + len] != 0) len++;

        if (len >= maxLen)
            throw new InvalidOperationException($"Unterminated string at RVA 0x{rva:X} - no null terminator found within {maxLen} bytes");

        return System.Text.Encoding.ASCII.GetString(image.AsSpan(offset, len));
    }

    /// <summary>
    /// Converts a Relative Virtual Address to file offset using section headers.
    /// </summary>
    /// <param name="rva">The relative virtual address to convert.</param>
    /// <param name="sections">The PE section headers.</param>
    /// <param name="imageSize">The total size of the PE image for bounds validation.</param>
    /// <returns>The file offset corresponding to the RVA.</returns>
    /// <exception cref="InvalidOperationException">Thrown when RVA cannot be mapped or results in out-of-bounds offset.</exception>
    private static int RvaToOffset(uint rva, IReadOnlyList<IMAGE_SECTION_HEADER> sections, int imageSize)
    {
        foreach (var section in sections)
        {
            var start = section.VirtualAddress;
            var end = start + Math.Max(section.SizeOfRawData, section.VirtualSize);
            if (rva >= start && rva < end)
            {
                int offset = (int)(rva - start + section.PointerToRawData);
                if (offset < 0 || offset >= imageSize)
                    throw new InvalidOperationException($"RVA 0x{rva:X} maps to invalid offset {offset} (image size: {imageSize})");
                return offset;
            }
        }

        // RVA might be in headers (before first section)
        if (rva < imageSize && sections.Count > 0 && rva < sections[0].VirtualAddress)
        {
            return (int)rva;
        }

        throw new InvalidOperationException($"RVA 0x{rva:X} not found in any section and not in headers");
    }

    /// <summary>
    /// Zeroes PE headers in remote memory for basic stealth.
    /// </summary>
    private static void EraseHeaders(nint hProcess, nint remoteBase, uint headerSize)
    {
        var zeros = new byte[headerSize];
        ProtectMemory(hProcess, remoteBase, headerSize, PAGE_READWRITE);
        WriteMemory(hProcess, remoteBase, zeros);
    }

    /// <summary>
    /// Registers exception handlers for the manually mapped DLL.
    /// This is critical for .NET AOT compiled DLLs and any code using SEH.
    /// Mimics what LoadLibrary does with RtlAddFunctionTable.
    /// </summary>
    private static void RegisterExceptionHandlers(nint hProcess, nint remoteBase, ReadOnlySpan<byte> localImage, IMAGE_NT_HEADERS64 nt, IReadOnlyList<IMAGE_SECTION_HEADER> sections)
    {
        var exceptionDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.EXCEPTION];
        if (exceptionDir.Size == 0)
        {
            Log.Debug("No exception directory - skipping exception handler registration");
            return;
        }

        var localArr = localImage.ToArray();
        int entryCount = (int)(exceptionDir.Size / Marshal.SizeOf<IMAGE_RUNTIME_FUNCTION_ENTRY>());
        Log.Debug("Exception directory has {Count} entries at RVA 0x{Rva:X}", entryCount, exceptionDir.VirtualAddress);

        // The RUNTIME_FUNCTION entries are already mapped at remoteBase + exception RVA
        var remoteFunctionTable = remoteBase + (int)exceptionDir.VirtualAddress;

        // Create a stub that calls RtlAddFunctionTable in the remote process
        // RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)
        var ntdllHandle = GetModuleHandle("ntdll.dll");
        var rtlAddFunctionTable = GetProcAddress(ntdllHandle, "RtlAddFunctionTable");
        if (rtlAddFunctionTable == nint.Zero)
        {
            Log.Warning("RtlAddFunctionTable not found - exception handlers will not be registered");
            return;
        }

        // Build a stub to call RtlAddFunctionTable:
        // mov rcx, FunctionTable
        // mov edx, EntryCount
        // mov r8, BaseAddress
        // mov rax, RtlAddFunctionTable
        // call rax
        // ret
        List<byte> b = [];
        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            var prefix = reg < 8 ? 0x48 : 0x49;
            var opcode = reg < 8 ? (byte)(0xB8 + reg) : (byte)(0xB8 + (reg - 8));
            Emit((byte)prefix, opcode);
            Emit(BitConverter.GetBytes(imm));
        }

        Emit(0x48, 0x83, 0xEC, 0x28); // sub rsp, 0x28 (shadow space + alignment)
        MovRegImm64(1, (ulong)remoteFunctionTable); // mov rcx, FunctionTable
        Emit(0xBA); Emit(BitConverter.GetBytes((uint)entryCount)); // mov edx, EntryCount
        MovRegImm64(8, (ulong)remoteBase); // mov r8, BaseAddress
        MovRegImm64(0, (ulong)rtlAddFunctionTable); // mov rax, RtlAddFunctionTable
        Emit(0xFF, 0xD0); // call rax
        Emit(0x48, 0x83, 0xC4, 0x28); // add rsp, 0x28
        Emit(0xC3); // ret

        var stub = b.ToArray();
        var remoteStub = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        try
        {
            WriteMemory(hProcess, remoteStub, stub);
            ProtectMemory(hProcess, remoteStub, (uint)stub.Length, PAGE_EXECUTE_READ);
            FlushInstructionCache(hProcess, remoteStub, (uint)stub.Length);

            // Execute the stub via CreateRemoteThread
            CreateRemoteThreadAndWait(hProcess, remoteStub, nint.Zero, wait: true);
            Log.Debug("Registered {Count} exception handlers at 0x{FuncTable:X}", entryCount, (ulong)remoteFunctionTable);
        }
        finally
        {
            FreeMemory(hProcess, remoteStub);
        }
    }

    /// <summary>
    /// Hijacks the first available thread to execute the loader stub.
    /// Prefers non-blocked threads but will wake blocked ones if needed.
    /// </summary>
    private static nint HijackFirstThread(int pid, nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt, InjectionMode.ThreadHijacking config)
    {
        var currentProcess = GetCurrentProcess();
        bool currentIs64 = IsProcess64Bit(currentProcess);
        bool targetIs64 = IsProcess64Bit(hProcess);

        Log.Debug("Architecture check: current process 64-bit={Current}, target process 64-bit={Target}", currentIs64, targetIs64);

        if (!targetIs64)
        {
            Log.Warning("Target process is 32-bit (WOW64). Thread-hijacking only supports x64");
            return nint.Zero;
        }

        if (config.EnableDebugPrivilege)
        {
            if (!EnableSeDebugPrivilege())
            {
                Log.Warning("Failed to enable SeDebugPrivilege - injection may fail for protected processes");
            }
        }

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

    private static nint HijackThread(ThreadInfo thread, nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt, InjectionMode.ThreadHijacking config, bool needsWakeup)
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
        public bool TryGetContext(out CONTEXT64 ctx)
        {
            ctx = default;
            var suspend = SuspendThread(Handle);
            if (suspend == 0xFFFFFFFF)
            {
                Log.Verbose("Thread {Tid}: SuspendThread failed (err {Err})", Id, Marshal.GetLastWin32Error());
                return false;
            }

            if (!TryGetThreadContext(Handle, out ctx))
            {
                ResumeThread(Handle);
                return false;
            }

            return true;
        }

        public bool TrySetContext(CONTEXT64 ctx)
        {
            bool success = TrySetThreadContext(Handle, ctx);
            if (!success)
                ResumeThread(Handle);
            return success;
        }

        public void ResumeCompletely()
        {
            uint count;
            do { count = ResumeThread(Handle); }
            while (count > 0 && count != 0xFFFFFFFF);
        }

        public void Dispose()
        {
            uint cnt;
            do { cnt = ResumeThread(Handle); } while (cnt > 0 && cnt != 0xFFFFFFFF);
            CloseHandleSafe(Handle);
        }
    }

    private sealed class ThreadSnapshot : IDisposable
    {
        private readonly nint _handle;
        private readonly int _pid;

        public ThreadSnapshot(int pid)
        {
            _pid = pid;
            _handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (_handle == nint.Zero) throw new System.ComponentModel.Win32Exception();
        }

        public IEnumerable<ThreadInfo> EnumerateThreads()
        {
            var entry = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };

            if (!Thread32First(_handle, ref entry)) yield break;

            do
            {
                if (entry.th32OwnerProcessID != (uint)_pid) continue;

                var hThread = OpenThread(THREAD_ALL_ACCESS, false, entry.th32ThreadID);
                if (hThread == nint.Zero) continue;

                var threadInfo = new ThreadInfo(entry.th32ThreadID, hThread);
                yield return threadInfo;
            }
            while (Thread32Next(_handle, ref entry));
        }

        public void Dispose() => CloseHandleSafe(_handle);
    }

    /// <summary>
    /// Creates and writes a loader stub that calls TLS callbacks and DllMain, then returns to original execution.
    /// </summary>
    private static (nint stubAddress, nint debugMarkerAddress) BuildAndWriteLoaderStub(nint hProcess, nint moduleBase, IMAGE_NT_HEADERS64 nt, nint originalRip, InjectionMode.ThreadHijacking config)
    {
        var dllMain = moduleBase + (int)nt.OptionalHeader.AddressOfEntryPoint;

        var tlsDir = nt.OptionalHeader.DataDirectory[(int)ImageDirectoryEntry.TLS];
        List<ulong> callbacks = [];
        uint tlsIndex = 0;
        ulong tlsDataPtr = 0;

        if (tlsDir.Size != 0)
        {
            var tlsRemote = ReadMemory(hProcess, moduleBase + (int)tlsDir.VirtualAddress, Marshal.SizeOf<IMAGE_TLS_DIRECTORY64>());
            var tlsStruct = BytesToStructure<IMAGE_TLS_DIRECTORY64>(tlsRemote, 0);

            // For implicit TLS, we need the loader's TLS index, not TlsAlloc's explicit index
            // The loader assigns implicit TLS indices sequentially starting from 0
            // For now, write 0 to AddressOfIndex and let the TLS callback try to handle it
            // TODO: Properly integrate with loader's TLS management
            if (tlsStruct.AddressOfIndex != 0)
            {
                // Don't use TlsAlloc - it's for explicit TLS, not implicit TLS
                // Just write 0 and see if TLS callback can work with it
                Log.Debug("TLS directory present, AddressOfIndex at 0x{Addr:X}", tlsStruct.AddressOfIndex);
                // Leave AddressOfIndex at its default value (from the DLL)
            }

            if (tlsStruct.AddressOfCallBacks != 0)
            {
                Log.Debug("Collecting TLS callbacks from 0x{CallbacksAddr:X}", tlsStruct.AddressOfCallBacks);
                ulong cbPtr = tlsStruct.AddressOfCallBacks;
                int callbackCount = 0;

                while (callbackCount < MAX_TLS_CALLBACKS)
                {
                    var buf = ReadMemory(hProcess, (nint)cbPtr, 8);
                    ulong cb = BitConverter.ToUInt64(buf);
                    if (cb == 0) break;
                    callbacks.Add(cb);
                    cbPtr += 8;
                    callbackCount++;
                }

                if (callbackCount >= MAX_TLS_CALLBACKS)
                {
                    Log.Warning("TLS callback collection stopped at limit ({Max}), possible corruption", MAX_TLS_CALLBACKS);
                }
            }
        }
        Log.Debug("Total TLS callbacks: {Count}", callbacks.Count);

        var arrBytes = new List<byte>();
        foreach (var c in callbacks) arrBytes.AddRange(BitConverter.GetBytes(c));
        arrBytes.AddRange(BitConverter.GetBytes((ulong)0));
        var callbacksRemote = AllocateMemory(hProcess, (uint)arrBytes.Count, PAGE_READWRITE);
        WriteMemory(hProcess, callbacksRemote, [.. arrBytes]);

        nint debugMarker = nint.Zero;
        if (config.EnableDebugMarker)
        {
            debugMarker = AllocateMemory(hProcess, 8, PAGE_READWRITE);
            WriteMemory(hProcess, debugMarker, BitConverter.GetBytes(DEBUG_MARKER_INITIAL));
            Log.Debug("Debug marker at 0x{Marker:X} (should change to 0x{Expected:X} after DllMain)", (ulong)debugMarker, DEBUG_MARKER_POST_DLLMAIN);
        }

        byte[] stub = BuildStubBytes((ulong)moduleBase, (ulong)dllMain, (ulong)callbacksRemote, (ulong)originalRip, (ulong)debugMarker, tlsIndex, tlsDataPtr);
        Log.Debug("Loader stub size {Size} bytes", stub.Length);

        if (config.LogGeneratedStub)
        {
            Log.Information("Generated stub bytes: {StubHex}", Convert.ToHexString(stub));
        }

        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, remote, stub);
        ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, remote, (uint)stub.Length);

        return (remote, debugMarker);
    }

    /// <summary>
    /// Generates x64 assembly stub that initializes TLS, calls TLS callbacks, DllMain, and jumps to original RIP.
    /// </summary>
    private static byte[] BuildStubBytes(ulong moduleBase, ulong dllMain, ulong callbacksAddr, ulong originalRip, ulong debugMarker, uint tlsIndex, ulong tlsDataPtr)
    {
        List<byte> b = [];

        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            var prefix = reg switch
            {
                < 8 => 0x48,
                _ => 0x49
            };
            var opcode = reg < 8 ? (byte)(0xB8 + reg) : (byte)(0xB8 + (reg - 8));
            Emit((byte)prefix, opcode);
            Emit(BitConverter.GetBytes(imm));
        }

        // 1. Save Complete CPU State
        Emit(0x9C); // pushfq
        Emit(0xFC); // cld (Clear Direction Flag)

        // Push GPRs: RAX, RCX, RDX, RBX, RBP, RSI, RDI
        Emit(0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57);
        // Push R8-R15
        Emit(0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57);

        // 2. Align Stack & Save Extended State
        Emit(0x48, 0x89, 0xE5);       // mov rbp, rsp        (Preserve stack pointer of saved regs)
        Emit(0x48, 0x83, 0xE4, 0xF0); // and rsp, -16        (Align stack to 16 bytes)
        Emit(0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00); // sub rsp, 512 (Reserve FXSAVE space)
        Emit(0x48, 0x0F, 0xAE, 0x04, 0x24); // fxsave64 [rsp] (Save XMM/FPU state)

        // 3. Shadow Space
        Emit(0x48, 0x83, 0xEC, 0x20); // sub rsp, 32

        // --- Body ---

        if (debugMarker != 0)
        {
            MovRegImm64(0, debugMarker);
            MovRegImm64(1, DEBUG_MARKER_ENTRY);
            Emit(0x48, 0x89, 0x08);
        }

        // Initialize TLS slot for this thread (must happen before TLS callbacks and DllMain)
        // Sets TEB->ThreadLocalStoragePointer[tlsIndex] = tlsDataPtr
        // Note: This uses implicit TLS array, not explicit TlsSlots
        if (tlsDataPtr != 0)
        {
            Emit(0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00); // mov rax, gs:[0x30] (TEB)
            Emit(0x48, 0x8B, 0x40, 0x58);                               // mov rax, [rax+0x58] (ThreadLocalStoragePointer)
            // Check if ThreadLocalStoragePointer is NULL
            Emit(0x48, 0x85, 0xC0);                                     // test rax, rax
            Emit(0x74, 0x00); int skipTlsPos = b.Count - 1;             // jz skip_tls_init
            MovRegImm64(1, tlsDataPtr);                                 // mov rcx, tlsDataPtr
            // mov [rax + tlsIndex*8], rcx
            Emit(0x48, 0x89, 0x88); Emit(BitConverter.GetBytes(tlsIndex * 8));
            b[skipTlsPos] = (byte)(b.Count - skipTlsPos - 1);           // patch jump offset

            if (debugMarker != 0)
            {
                // Write 0xAAAA... if TLS init succeeded
                MovRegImm64(0, debugMarker);
                MovRegImm64(1, 0xAAAAAAAAAAAAAAAA);
                Emit(0x48, 0x89, 0x08);
            }
        }

        // NOTE: For CRT DLLs, we skip calling TLS callbacks ourselves.
        // The CRT entry point (_DllMainCRTStartup) handles TLS initialization internally.
        // Calling TLS callbacks before CRT initialization can cause crashes.
        // TODO: Consider making this configurable
        /*
        if (callbacksAddr != 0)
        {
            MovRegImm64(3, callbacksAddr); // RBX = callbacks array
            int loopLabel = b.Count;
            Emit(0x48, 0x8B, 0x03); // mov rax, [rbx]
            Emit(0x48, 0x85, 0xC0); // test rax, rax
            Emit(0x74, 0x00); int jePos = b.Count - 1;

            MovRegImm64(1, moduleBase);
            Emit(0xBA, 0x01, 0x00, 0x00, 0x00); // mov edx, 1
            Emit(0x41, 0x31, 0xC0); // xor r8d, r8d
            Emit(0xFF, 0xD0); // call rax

            Emit(0x48, 0x83, 0xC3, 0x08);
            Emit(0xEB, (byte)(loopLabel - (b.Count + 1)));

            b[jePos] = (byte)(b.Count - (jePos + 1));
        }
        */

        if (debugMarker != 0)
        {
            MovRegImm64(0, debugMarker);
            MovRegImm64(1, DEBUG_MARKER_PRE_DLLMAIN);
            Emit(0x48, 0x89, 0x08);
        }

        MovRegImm64(1, moduleBase); // RCX
        Emit(0xBA, 0x01, 0x00, 0x00, 0x00); // RDX = 1
        Emit(0x41, 0x31, 0xC0); // R8 = 0
        MovRegImm64(0, dllMain); // RAX
        Emit(0xFF, 0xD0); // call DllMain

        if (debugMarker != 0)
        {
            MovRegImm64(0, debugMarker);
            MovRegImm64(1, DEBUG_MARKER_POST_DLLMAIN);
            Emit(0x48, 0x89, 0x08);
        }

        // --- Restore ---

        Emit(0x48, 0x83, 0xC4, 0x20); // add rsp, 32
        Emit(0x48, 0x0F, 0xAE, 0x0C, 0x24); // fxrstor64 [rsp]
        Emit(0x48, 0x89, 0xEC);       // mov rsp, rbp        (Restore original stack pointer)

        // Pop R8-R15
        Emit(0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58);
        // Pop RDI, RSI, RBP, RBX, RDX, RCX, RAX
        Emit(0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58);
        
        Emit(0x9D); // popfq

        switch (originalRip)
        {
            case 0:
                Emit(0xC3);
                break;
            default:
                MovRegImm64(0, originalRip);
                Emit(0xFF, 0xE0);
                break;
        }

        return [.. b];
    }

    /// <summary>
    /// Unlinks the mapped module from PEB lists for basic stealth.
    /// Note: PEB offsets are for Windows 10/11 x64. Different OS versions may have different offsets.
    /// </summary>
    private static void UnlinkFromPEB(nint hProcess, nint moduleBase)
    {
        var status = NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, out var pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
        if (status != 0)
        {
            Log.Warning("NtQueryInformationProcess failed with status 0x{Status:X}", status);
            return;
        }

        nint peb = pbi.PebBaseAddress;
        if (peb == nint.Zero)
        {
            Log.Warning("PEB base address is null");
            return;
        }


        // Helper to safely read a pointer from remote memory
        bool TryReadPointer(nint address, out nint value)
        {
            value = nint.Zero;
            byte[] buf = new byte[8];
            if (!ReadProcessMemory(hProcess, address, buf, 8, out var bytesRead) || bytesRead < 8)
            {
                Log.Verbose("Failed to read pointer at 0x{Address:X}", (ulong)address);
                return false;
            }
            value = (nint)BitConverter.ToInt64(buf);
            return true;
        }

        // Read PEB.Ldr
        if (!TryReadPointer(peb + PEB_LDR_OFFSET, out nint ldr) || ldr == nint.Zero)
        {
            Log.Warning("Failed to read PEB.Ldr or Ldr is null");
            return;
        }

        // Read InLoadOrderModuleList head
        if (!TryReadPointer(ldr + LDR_IN_LOAD_ORDER_OFFSET, out nint listHead) || listHead == nint.Zero)
        {
            Log.Warning("Failed to read InLoadOrderModuleList head");
            return;
        }

        nint current = listHead;
        int iterations = 0;

        while (iterations++ < MAX_PEB_LIST_ITERATIONS)
        {
            // Read DllBase for current entry
            if (!TryReadPointer(current + LDR_ENTRY_DLLBASE_OFFSET, out nint dllBaseRead))
            {
                Log.Warning("Failed to read DllBase at entry 0x{Entry:X}", (ulong)current);
                break;
            }

            if (dllBaseRead == moduleBase)
            {
                Log.Debug("Found module at entry 0x{Entry:X}, unlinking from PEB lists", (ulong)current);

                bool UnlinkFromList(int offset, string listName)
                {
                    if (!TryReadPointer(current + offset, out nint flink) ||
                        !TryReadPointer(current + offset + 8, out nint blink))
                    {
                        Log.Warning("Failed to read {ListName} links", listName);
                        return false;
                    }

                    if (flink == nint.Zero || blink == nint.Zero)
                    {
                        Log.Verbose("{ListName}: flink or blink is null, skipping", listName);
                        return true; // Not an error, just not linked in this list
                    }

                    try
                    {
                        // Update blink->Flink to point to flink
                        WriteMemory(hProcess, blink, BitConverter.GetBytes((ulong)flink));
                        // Update flink->Blink to point to blink
                        WriteMemory(hProcess, flink + 8, BitConverter.GetBytes((ulong)blink));
                        Log.Verbose("Unlinked from {ListName}", listName);
                        return true;
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "Failed to unlink from {ListName}", listName);
                        return false;
                    }
                }

                UnlinkFromList(LDR_ENTRY_IN_LOAD_OFFSET, "InLoadOrderLinks");
                UnlinkFromList(LDR_ENTRY_IN_MEMORY_OFFSET, "InMemoryOrderLinks");
                UnlinkFromList(LDR_ENTRY_IN_INIT_OFFSET, "InInitializationOrderLinks");
                return;
            }

            // Move to next entry (Flink)
            if (!TryReadPointer(current, out nint next))
            {
                Log.Warning("Failed to read next entry pointer");
                break;
            }

            current = next;
            if (current == listHead || current == nint.Zero)
            {
                Log.Debug("Reached end of module list without finding target module");
                break;
            }
        }

        if (iterations >= MAX_PEB_LIST_ITERATIONS)
        {
            Log.Warning("PEB list traversal exceeded maximum iterations ({Max}), possible corruption", MAX_PEB_LIST_ITERATIONS);
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
            var prefix = reg switch
            {
                < 8 => 0x48,
                _ => 0x49
            };
            var opcode = reg < 8 ? (byte)(0xB8 + reg) : (byte)(0xB8 + (reg - 8));
            Emit((byte)prefix, opcode);
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
        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, remote, stub);
        ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, remote, (uint)stub.Length);
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
        var hCurrentProcess = GetCurrentProcess();

        foreach (var name in names)
        {
            var h = GetModuleHandle(name);
            if (h != nint.Zero)
            {
                // Try to get actual module size from MODULEINFO
                if (GetModuleInformation(hCurrentProcess, h, out var modInfo, (uint)Marshal.SizeOf<MODULEINFO>()))
                {
                    list.Add(((ulong)h, modInfo.SizeOfImage));
                    Log.Verbose("System module {Name}: base=0x{Base:X}, size=0x{Size:X}", name, (ulong)h, modInfo.SizeOfImage);
                }
                else
                {
                    // Fallback: use a conservative default size if GetModuleInformation fails
                    list.Add(((ulong)h, DEFAULT_MODULE_SIZE_FALLBACK));
                    Log.Verbose("System module {Name}: base=0x{Base:X}, size=0x{Size:X} (fallback)", name, (ulong)h, DEFAULT_MODULE_SIZE_FALLBACK);
                }
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
        PostThreadMessage(tid, WM_NULL, 0, nint.Zero);
        NtAlertThread(hThread);
    }

    private static nint CreateDllLoadWrapper(nint hProcess, ulong ldrLoadDllAddr, ulong remoteUnicodeAddr, ulong remoteHandleAddr)
    {
        List<byte> b = [];
        void Emit(params byte[] bytes) => b.AddRange(bytes);
        void MovRegImm64(byte reg, ulong imm)
        {
            var prefix = reg switch
            {
                < 8 => 0x48,
                _ => 0x49
            };
            var opcode = reg < 8 ? (byte)(0xB8 + reg) : (byte)(0xB8 + (reg - 8));
            Emit((byte)prefix, opcode);
            Emit(BitConverter.GetBytes(imm));
        }

        Emit(0x48, 0x83, 0xEC, 0x28);
        MovRegImm64(1, 0);            // RCX = PathToFile (NULL)
        MovRegImm64(2, 0);            // RDX = Flags (0)
        MovRegImm64(8, remoteUnicodeAddr); // R8  = PUNICODE_STRING
        MovRegImm64(9, remoteHandleAddr);  // R9  = Module handle out
        MovRegImm64(10, ldrLoadDllAddr);   // R10 = LdrLoadDll
        Emit(0x41, 0xFF, 0xD2);            // call r10
        Emit(0x48, 0x83, 0xC4, 0x28);
        Emit(0xC3);

        var stub = b.ToArray();
        var remote = AllocateMemory(hProcess, (uint)stub.Length, PAGE_READWRITE);
        WriteMemory(hProcess, remote, stub);
        ProtectMemory(hProcess, remote, (uint)stub.Length, PAGE_EXECUTE_READ);
        FlushInstructionCache(hProcess, remote, (uint)stub.Length);
        return remote;
    }

    /// <summary>
    /// Initializes the TLS data slot for implicit TLS (IMAGE_TLS_DIRECTORY) in the current thread.
    /// Sets TEB->ThreadLocalStoragePointer[index] = dataPtr.
    /// </summary>
    private static void InitializeTlsSlotRemote(nint hProcess, uint tlsIndex, nint dataPtr)
    {
        // Build stub that:
        // 1. Gets TEB from GS:[0x30]
        // 2. Gets ThreadLocalStoragePointer from TEB+0x58
        // 3. Writes dataPtr to ThreadLocalStoragePointer[index]
        //
        // x64 assembly:
        //   mov rax, gs:[0x30]          ; TEB
        //   mov rax, [rax + 0x58]       ; ThreadLocalStoragePointer
        //   mov rcx, dataPtr
        //   mov [rax + index*8], rcx
        //   ret

        List<byte> b = [];
        void Emit(params byte[] bytes) => b.AddRange(bytes);

        Emit(0x48, 0x83, 0xEC, 0x28);                                     // sub rsp, 0x28
        Emit(0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00);       // mov rax, gs:[0x30] (TEB)
        Emit(0x48, 0x8B, 0x40, 0x58);                                     // mov rax, [rax+0x58] (ThreadLocalStoragePointer)
        Emit(0x48, 0xB9); Emit(BitConverter.GetBytes((ulong)dataPtr));    // mov rcx, dataPtr
        // mov [rax + disp32], rcx - ModRM: mod=10, reg=rcx(001), rm=rax(000) = 0x88
        Emit(0x48, 0x89, 0x88); Emit(BitConverter.GetBytes(tlsIndex * 8)); // mov [rax+index*8], rcx
        Emit(0x48, 0x83, 0xC4, 0x28);                                     // add rsp, 0x28
        Emit(0xC3);                                                       // ret

        var stub = b.ToArray();
        var remoteStub = AllocateMemory(hProcess, (uint)stub.Length, PAGE_EXECUTE_READWRITE);
        WriteMemory(hProcess, remoteStub, stub);

        try
        {
            CreateRemoteThreadAndWait(hProcess, remoteStub, nint.Zero, wait: true);
        }
        finally
        {
            FreeMemory(hProcess, remoteStub);
        }
    }

    /// <summary>
    /// Allocates a TLS index in the remote process via TlsAlloc().
    /// This is required for manually mapped DLLs that use thread-local storage.
    /// </summary>
    private static uint AllocateTlsIndexRemote(nint hProcess)
    {
        var kernel32 = GetModuleHandle("kernel32.dll");
        var tlsAlloc = GetProcAddress(kernel32, "TlsAlloc");
        if (tlsAlloc == nint.Zero)
            throw new Exception("TlsAlloc not found in kernel32.dll");

        var resultAddr = AllocateMemory(hProcess, 4, PAGE_READWRITE);

        // Build stub: call TlsAlloc, store result, ret
        List<byte> b = [];
        void Emit(params byte[] bytes) => b.AddRange(bytes);

        Emit(0x48, 0x83, 0xEC, 0x28);                                      // sub rsp, 0x28
        Emit(0x48, 0xB8); Emit(BitConverter.GetBytes((ulong)tlsAlloc));    // mov rax, TlsAlloc
        Emit(0xFF, 0xD0);                                                  // call rax
        Emit(0x48, 0xB9); Emit(BitConverter.GetBytes((ulong)resultAddr));  // mov rcx, resultAddr
        Emit(0x89, 0x01);                                                  // mov [rcx], eax
        Emit(0x48, 0x83, 0xC4, 0x28);                                      // add rsp, 0x28
        Emit(0xC3);                                                        // ret

        var stub = b.ToArray();
        var remoteStub = AllocateMemory(hProcess, (uint)stub.Length, PAGE_EXECUTE_READWRITE);
        WriteMemory(hProcess, remoteStub, stub);

        try
        {
            CreateRemoteThreadAndWait(hProcess, remoteStub, nint.Zero, wait: true);
            var resultBytes = ReadMemory(hProcess, resultAddr, 4);
            return BitConverter.ToUInt32(resultBytes);
        }
        finally
        {
            FreeMemory(hProcess, remoteStub);
            FreeMemory(hProcess, resultAddr);
        }
    }

    /// <summary>
    /// Loads a DLL into the remote process using CreateRemoteThread and LdrLoadDll.
    /// Returns the actual module handle that Windows returned (important for API Set DLLs
    /// which resolve to different real DLLs like kernelbase.dll or ucrtbase.dll).
    /// </summary>
    private static nint LoadLibraryViaRemoteThread(nint hProcess, string dllName)
    {
        nint remoteStr = nint.Zero, remoteUnicode = nint.Zero, remoteHandle = nint.Zero, wrapper = nint.Zero;
        nint loadedHandle = nint.Zero;

        try
        {
            var wideBytes = System.Text.Encoding.Unicode.GetBytes(dllName + "\0");
            remoteStr = AllocateMemory(hProcess, (uint)wideBytes.Length, PAGE_READWRITE);
            WriteMemory(hProcess, remoteStr, wideBytes);

            // Build UNICODE_STRING structure
            ushort len = (ushort)(wideBytes.Length - 2); // Length excluding null terminator
            var unicodeBuf = new byte[16];
            BitConverter.GetBytes(len).CopyTo(unicodeBuf, 0);                    // Length
            BitConverter.GetBytes((ushort)wideBytes.Length).CopyTo(unicodeBuf, 2); // MaximumLength
            BitConverter.GetBytes((ulong)remoteStr).CopyTo(unicodeBuf, 8);        // Buffer (at offset 8 for x64 alignment)
            remoteUnicode = AllocateMemory(hProcess, 16, PAGE_READWRITE);
            WriteMemory(hProcess, remoteUnicode, unicodeBuf);

            remoteHandle = AllocateMemory(hProcess, 8, PAGE_READWRITE);
            WriteMemory(hProcess, remoteHandle, new byte[8]);

            var ldrLoadDll = GetProcAddress(GetModuleHandle("ntdll.dll"), "LdrLoadDll");
            wrapper = CreateDllLoadWrapper(hProcess, (ulong)ldrLoadDll, (ulong)remoteUnicode, (ulong)remoteHandle);

            // Use CreateRemoteThread and WAIT for completion
            CreateRemoteThreadAndWait(hProcess, wrapper, nint.Zero, wait: true);

            // Read the module handle that LdrLoadDll returned
            // This is critical for API Set DLLs which resolve to real DLLs like kernelbase.dll
            var handleBytes = ReadMemory(hProcess, remoteHandle, 8);
            loadedHandle = (nint)BitConverter.ToInt64(handleBytes);
            Log.Debug("LdrLoadDll returned handle 0x{Handle:X} for {Dll}", (ulong)loadedHandle, dllName);
        }
        finally
        {
            if (wrapper != nint.Zero) try { FreeMemory(hProcess, wrapper); } catch { /* ignore cleanup errors */ }
            if (remoteStr != nint.Zero) try { FreeMemory(hProcess, remoteStr); } catch { /* ignore cleanup errors */ }
            if (remoteUnicode != nint.Zero) try { FreeMemory(hProcess, remoteUnicode); } catch { /* ignore cleanup errors */ }
            if (remoteHandle != nint.Zero) try { FreeMemory(hProcess, remoteHandle); } catch { /* ignore cleanup errors */ }
        }

        return loadedHandle;
    }

}