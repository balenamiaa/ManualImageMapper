using System.Runtime.InteropServices;
using Serilog;
using static ManualImageMapper.Interop.Structures;

namespace ManualImageMapper.Interop;

/// <summary>
/// Tracks every remote allocation made by <see cref="PebLinker.BuildLdrEntry"/> so the host
/// can erase + free them after unlinking — leaves no LDR-shaped artifact in the target.
/// </summary>
public readonly record struct PebLinkResult(
    nint LdrEntry,
    nint DdagNode,
    nint BaseDllName,
    nint FullDllName,
    int LdrEntrySize,
    int DdagNodeSize,
    int BaseDllNameSize,
    int FullDllNameSize)
{
    public static PebLinkResult Empty => default;
    public bool IsEmpty => LdrEntry == nint.Zero;
}

/// <summary>
/// Bundle of PEB-side addresses that a hijack/CRT stub needs to splice the new module into the
/// loader's three doubly-linked module lists. The stub does the inserts under loader lock;
/// nothing here mutates the target — this is just metadata produced by <see cref="PebLinker.BuildLdrEntry"/>.
/// </summary>
public readonly record struct LdrStructures(
    PebLinkResult Allocations,
    nint Ldr,
    nint InLoadOrderHead,
    nint InMemoryOrderHead,
    nint InInitializationOrderHead,
    nint InLoadOrderEntryAddr,
    nint InMemoryOrderEntryAddr,
    nint InInitializationOrderEntryAddr)
{
    public static LdrStructures Empty => default;
    public bool IsEmpty => Allocations.IsEmpty;
}

/// <summary>
/// Handles linking manually mapped modules into the Windows loader's
/// PEB data structures. Required for CRT/TLS support.
/// </summary>
public static class PebLinker
{
    private static readonly ILogger Log = Serilog.Log.ForContext("SourceContext", nameof(PebLinker));

    /// <summary>
    /// Links a manually mapped module into the Windows loader's PEB structures.
    ///
    /// This creates an LDR_DATA_TABLE_ENTRY for the module and inserts it into
    /// the three PEB module lists. This is required for:
    /// - CRT initialization (it checks if module is registered)
    /// - TLS support (LdrpHandleTlsData needs the entry)
    /// - Various APIs that query module lists
    ///
    /// The entry is NOT freed after use - it must stay linked for the module to function correctly.
    /// In the stub-based flow it's unlinked in-target under loader lock; <see cref="UnlinkFromPEB"/>
    /// remains as a host-side fallback (e.g. when the stub fails before unlinking itself).
    /// </summary>
    /// <summary>
    /// Allocates and initializes the LDR_DATA_TABLE_ENTRY (and friends) inside the target process,
    /// but does <strong>not</strong> insert it into the PEB's three module lists. The caller's stub
    /// performs the inserts under loader lock to avoid racing with the target's own loader.
    /// </summary>
    /// <returns>Allocation tracker + listHead/entry addresses for stub-side linking, or <see cref="LdrStructures.Empty"/> on failure.</returns>
    public static LdrStructures BuildLdrEntry(
        nint hProcess,
        int pid,
        nint moduleBase,
        uint sizeOfImage,
        nint entryPoint,
        ulong originalImageBase,
        string dllName,
        string fullDllPath)
    {
        Log.Debug("Building LDR entry for: {DllName} at 0x{Base:X}", dllName, (ulong)moduleBase);

        // Get PEB address via NtQueryInformationProcess
        var status = NativeMethods.NtQueryInformationProcess(
            hProcess,
            PROCESSINFOCLASS.ProcessBasicInformation,
            out var pbi,
            Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(),
            out _);

        if (status != 0 || pbi.PebBaseAddress == nint.Zero)
        {
            Log.Warning("Failed to get PEB address, status=0x{Status:X}", status);
            return LdrStructures.Empty;
        }

        // Read PEB.Ldr pointer
        var ldrBytes = MemoryHelpers.ReadMemory(hProcess, pbi.PebBaseAddress + Constants.PEB_LDR_OFFSET, 8);
        var ldr = (nint)BitConverter.ToInt64(ldrBytes);
        if (ldr == nint.Zero)
        {
            Log.Warning("PEB.Ldr is null");
            return LdrStructures.Empty;
        }

        Log.Debug("PEB=0x{Peb:X}, Ldr=0x{Ldr:X}", (ulong)pbi.PebBaseAddress, (ulong)ldr);

        // Allocate strings in remote process
        var dllNameWide = System.Text.Encoding.Unicode.GetBytes(dllName + "\0");
        var fullPathWide = System.Text.Encoding.Unicode.GetBytes(fullDllPath + "\0");
        int dllNameSize = dllNameWide.Length;
        int fullPathSize = fullPathWide.Length;

        var remoteDllName = MemoryHelpers.AllocateMemory(hProcess, (uint)dllNameSize);
        var remoteFullPath = MemoryHelpers.AllocateMemory(hProcess, (uint)fullPathSize);
        MemoryHelpers.WriteMemory(hProcess, remoteDllName, dllNameWide);
        MemoryHelpers.WriteMemory(hProcess, remoteFullPath, fullPathWide);

        // Allocate LDR_DDAG_NODE (for module dependency tracking)
        int ddagSize = Marshal.SizeOf<LDR_DDAG_NODE>();
        var remoteDdagNode = MemoryHelpers.AllocateMemory(hProcess, (uint)ddagSize);

        // Allocate LDR_DATA_TABLE_ENTRY
        int entrySize = Marshal.SizeOf<LDR_DATA_TABLE_ENTRY>();
        var remoteLdrEntry = MemoryHelpers.AllocateMemory(hProcess, (uint)entrySize);

        Log.Debug("Allocated: LdrEntry=0x{Entry:X}, DdagNode=0x{Ddag:X}",
            (ulong)remoteLdrEntry, (ulong)remoteDdagNode);

        // Initialize LDR_DDAG_NODE
        var ddagNode = new LDR_DDAG_NODE
        {
            Modules = new LIST_ENTRY
            {
                Flink = remoteLdrEntry + (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("NodeModuleLink"),
                Blink = remoteLdrEntry + (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("NodeModuleLink")
            },
            LoadCount = 1,
            State = LDR_DDAG_STATE.LdrModulesReadyToRun
        };
        MemoryHelpers.WriteMemory(hProcess, remoteDdagNode, MemoryHelpers.StructureToBytes(ddagNode));

        // Initialize LDR_DATA_TABLE_ENTRY
        var ldrEntry = new LDR_DATA_TABLE_ENTRY
        {
            DllBase = moduleBase,
            EntryPoint = entryPoint,
            SizeOfImage = sizeOfImage,
            FullDllName = new UNICODE_STRING
            {
                Length = (ushort)(fullPathWide.Length - 2),
                MaximumLength = (ushort)fullPathWide.Length,
                Buffer = remoteFullPath
            },
            BaseDllName = new UNICODE_STRING
            {
                Length = (ushort)(dllNameWide.Length - 2),
                MaximumLength = (ushort)dllNameWide.Length,
                Buffer = remoteDllName
            },
            Flags = LdrFlags.LDRP_IMAGE_DLL | LdrFlags.LDRP_ENTRY_INSERTED |
                    LdrFlags.LDRP_ENTRY_PROCESSED | LdrFlags.LDRP_PROCESS_ATTACH_CALLED,
            ObsoleteLoadCount = 1,
            TlsIndex = 0xFFFF,  // Will be set by LdrpHandleTlsData if TLS is present
            DdagNode = remoteDdagNode,
            NodeModuleLink = new LIST_ENTRY
            {
                Flink = remoteDdagNode,
                Blink = remoteDdagNode
            },
            OriginalBase = originalImageBase,
            BaseNameHashValue = ComputeModuleNameHash(dllName),
            LoadReason = LDR_DLL_LOAD_REASON.LoadReasonDynamicLoad,
            ReferenceCount = 1
        };

        // Set relocated flag if module is not at preferred base
        if ((ulong)moduleBase != originalImageBase)
        {
            ldrEntry.Flags |= LdrFlags.LDRP_IMAGE_NOT_AT_BASE;
        }

        MemoryHelpers.WriteMemory(hProcess, remoteLdrEntry, MemoryHelpers.StructureToBytes(ldrEntry));

        // Compute addresses the stub needs to link the entry into PEB's three lists.
        // The stub does the InsertTailList sequence under loader lock; the host only allocates.
        int inLoadOrderOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InLoadOrderLinks");
        int inMemoryOrderOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InMemoryOrderLinks");
        int inInitOrderOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InInitializationOrderLinks");

        var allocations = new PebLinkResult(
            remoteLdrEntry, remoteDdagNode, remoteDllName, remoteFullPath,
            entrySize, ddagSize, dllNameSize, fullPathSize);

        Log.Debug("LDR entry built: {DllName} - stub will link to PEB under loader lock", dllName);
        return new LdrStructures(
            allocations,
            ldr,
            ldr + 0x10,
            ldr + 0x20,
            ldr + 0x30,
            remoteLdrEntry + inLoadOrderOffset,
            remoteLdrEntry + inMemoryOrderOffset,
            remoteLdrEntry + inInitOrderOffset);
    }

    /// <summary>
    /// Zeroes and frees every allocation produced by <see cref="BuildLdrEntry"/>.
    /// Call this only after the entry has been unlinked from the PEB lists (typically by the
    /// hijack/CRT stub under loader lock) so no thread can still reach it.
    /// </summary>
    public static void FreePebLinkAllocations(nint hProcess, in PebLinkResult result)
    {
        if (result.IsEmpty) return;

        TryEraseAndFree(hProcess, result.LdrEntry, result.LdrEntrySize);
        TryEraseAndFree(hProcess, result.DdagNode, result.DdagNodeSize);
        TryEraseAndFree(hProcess, result.BaseDllName, result.BaseDllNameSize);
        TryEraseAndFree(hProcess, result.FullDllName, result.FullDllNameSize);
    }

    private static void TryEraseAndFree(nint hProcess, nint addr, int size)
    {
        if (addr == nint.Zero || size <= 0) return;
        try
        {
            MemoryHelpers.WriteMemory(hProcess, addr, new byte[size]);
            MemoryHelpers.FreeMemory(hProcess, addr);
        }
        catch (Exception ex)
        {
            Log.Verbose(ex, "Failed to erase/free 0x{Addr:X} ({Size} bytes)", (ulong)addr, size);
        }
    }

    /// <summary>
    /// Initializes CRT support by linking the module to PEB only.
    /// Does NOT call LdrpHandleTlsData - this must be called from the
    /// thread that will execute the DLL code (hijacked thread or main thread).
    ///
    /// Also returns the LdrpHandleTlsData address so the caller can call it
    /// from the correct thread context.
    /// </summary>
    /// <returns>Tuple of (LDR structure metadata, LdrpHandleTlsData address) - either may be empty/zero on partial failure.</returns>
    public static (LdrStructures structures, nint ldrpHandleTlsDataAddr) InitializeCrtModulePebOnly(
        nint hProcess,
        int pid,
        nint moduleBase,
        uint sizeOfImage,
        nint entryPoint,
        ulong originalImageBase,
        string dllName)
    {
        string fullPath = $"C:\\Windows\\System32\\{dllName}";

        var structures = BuildLdrEntry(hProcess, pid, moduleBase, sizeOfImage,
            entryPoint, originalImageBase, dllName, fullPath);

        if (structures.IsEmpty)
        {
            Log.Warning("Failed to build LDR entry");
            return (LdrStructures.Empty, nint.Zero);
        }

        // Find LdrpHandleTlsData address but don't call it yet
        var funcOffset = PatternScanner.FindLdrpHandleTlsDataOffset();
        if (funcOffset < 0)
        {
            Log.Warning("LdrpHandleTlsData not found - TLS may not work correctly");
            return (structures, nint.Zero);
        }

        var remoteNtdll = ModuleHelpers.GetRemoteModuleHandle(hProcess, pid, "ntdll.dll");
        if (remoteNtdll == nint.Zero)
        {
            Log.Warning("Could not find ntdll.dll in remote process");
            return (structures, nint.Zero);
        }

        var ldrpHandleTlsData = remoteNtdll + funcOffset;
        Log.Debug("LdrpHandleTlsData at 0x{Addr:X}, LDR entry at 0x{Entry:X} - will be called from stub",
            (ulong)ldrpHandleTlsData, (ulong)structures.Allocations.LdrEntry);

        return (structures, ldrpHandleTlsData);
    }

    /// <summary>
    /// Unlinks a module from all PEB lists (for stealth).
    /// Call this after DllMain has executed.
    /// </summary>
    public static void UnlinkFromPEB(nint hProcess, nint moduleBase)
    {
        var status = NativeMethods.NtQueryInformationProcess(
            hProcess,
            PROCESSINFOCLASS.ProcessBasicInformation,
            out var pbi,
            Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(),
            out _);

        if (status != 0 || pbi.PebBaseAddress == nint.Zero)
        {
            Log.Warning("NtQueryInformationProcess failed with status 0x{Status:X}", status);
            return;
        }

        if (!TryReadPointer(hProcess, pbi.PebBaseAddress + Constants.PEB_LDR_OFFSET, out nint ldr) || ldr == nint.Zero)
        {
            Log.Warning("Failed to read PEB.Ldr or Ldr is null");
            return;
        }

        if (!TryReadPointer(hProcess, ldr + Constants.LDR_IN_LOAD_ORDER_OFFSET, out nint listHead) || listHead == nint.Zero)
        {
            Log.Warning("Failed to read InLoadOrderModuleList head");
            return;
        }

        nint current = listHead;
        int iterations = 0;

        while (iterations++ < Constants.MAX_PEB_LIST_ITERATIONS)
        {
            if (!TryReadPointer(hProcess, current + Constants.LDR_ENTRY_DLLBASE_OFFSET, out nint dllBaseRead))
            {
                Log.Warning("Failed to read DllBase at entry 0x{Entry:X}", (ulong)current);
                break;
            }

            if (dllBaseRead == moduleBase)
            {
                Log.Debug("Found module at entry 0x{Entry:X}, unlinking", (ulong)current);

                UnlinkFromList(hProcess, current, Constants.LDR_ENTRY_IN_LOAD_OFFSET, "InLoadOrderLinks");
                UnlinkFromList(hProcess, current, Constants.LDR_ENTRY_IN_MEMORY_OFFSET, "InMemoryOrderLinks");
                UnlinkFromList(hProcess, current, Constants.LDR_ENTRY_IN_INIT_OFFSET, "InInitializationOrderLinks");
                return;
            }

            if (!TryReadPointer(hProcess, current, out nint next))
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

        if (iterations >= Constants.MAX_PEB_LIST_ITERATIONS)
            Log.Warning("PEB list traversal exceeded maximum iterations");
    }

    #region Private Helpers

    private static bool TryReadPointer(nint hProcess, nint address, out nint value)
    {
        value = nint.Zero;
        byte[] buf = new byte[8];
        if (!NativeMethods.ReadProcessMemory(hProcess, address, buf, 8, out var bytesRead) || bytesRead < 8)
            return false;
        value = (nint)BitConverter.ToInt64(buf);
        return true;
    }

    private static void UnlinkFromList(nint hProcess, nint current, int offset, string listName)
    {
        if (!TryReadPointer(hProcess, current + offset, out nint flink) ||
            !TryReadPointer(hProcess, current + offset + 8, out nint blink))
            return;

        if (flink == nint.Zero || blink == nint.Zero)
            return;

        try
        {
            MemoryHelpers.WriteMemory(hProcess, blink, BitConverter.GetBytes((ulong)flink));
            MemoryHelpers.WriteMemory(hProcess, flink + 8, BitConverter.GetBytes((ulong)blink));
            Log.Verbose("Unlinked from {ListName}", listName);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to unlink from {ListName}", listName);
        }
    }

    /// <summary>
    /// Computes a hash of the DLL name (same algorithm as Windows loader).
    /// </summary>
    public static uint ComputeModuleNameHash(string dllName)
    {
        uint hash = 0;
        foreach (char c in dllName.ToUpperInvariant())
            hash = (hash * 0x1003F) + c;
        return hash;
    }

    #endregion
}
