// =============================================================================
// PebLinker.cs - PEB Integration and CRT Initialization
// =============================================================================
//
// This module handles linking manually mapped modules into the Windows loader's
// Process Environment Block (PEB) data structures. This is CRITICAL for CRT
// support because the C Runtime expects modules to be registered with the loader.
//
// WHY PEB LINKING IS NECESSARY:
// -----------------------------
// When Windows loads a DLL normally (LoadLibrary), it:
// 1. Creates an LDR_DATA_TABLE_ENTRY structure for the module
// 2. Links it into three doubly-linked lists in the PEB
// 3. Calls LdrpHandleTlsData to initialize Thread Local Storage
// 4. Calls DllMain
//
// For manually mapped DLLs, we must do steps 1-3 ourselves. Without this:
// - CRT initialization fails (it checks loader data structures)
// - TLS doesn't work (errno, thread-local state, etc.)
// - Some APIs fail (they query module lists)
//
// PEB STRUCTURE OVERVIEW:
// -----------------------
// PEB (Process Environment Block)
//   └─ Ldr (PEB_LDR_DATA)
//        ├─ InLoadOrderModuleList      - All modules in load order
//        ├─ InMemoryOrderModuleList    - All modules by memory address
//        └─ InInitializationOrderModuleList - Modules in init order
//
// Each list contains LDR_DATA_TABLE_ENTRY structures linked together.
// We create a new entry and insert it at the tail of each list.
//
// MAINTENANCE NOTES:
// - PEB/LDR offsets are Windows version specific (see Constants.cs)
// - The LDR_DATA_TABLE_ENTRY layout changes between Windows versions
// - Always test CRT DLLs after Windows updates
// =============================================================================

using System.Runtime.InteropServices;
using Serilog;
using static ManualImageMapper.Interop.Structures;

namespace ManualImageMapper.Interop;

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
    /// The entry is NOT freed after use - it must stay linked for the module
    /// to function correctly. It will be unlinked later by UnlinkFromPEB.
    /// </summary>
    /// <returns>Address of the LDR_DATA_TABLE_ENTRY in remote process, or Zero on failure.</returns>
    public static nint LinkModuleToPEB(
        nint hProcess,
        int pid,
        nint moduleBase,
        uint sizeOfImage,
        nint entryPoint,
        ulong originalImageBase,
        string dllName,
        string fullDllPath)
    {
        Log.Debug("Linking module to PEB: {DllName} at 0x{Base:X}", dllName, (ulong)moduleBase);

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
            return nint.Zero;
        }

        // Read PEB.Ldr pointer
        var ldrBytes = MemoryHelpers.ReadMemory(hProcess, pbi.PebBaseAddress + Constants.PEB_LDR_OFFSET, 8);
        var ldr = (nint)BitConverter.ToInt64(ldrBytes);
        if (ldr == nint.Zero)
        {
            Log.Warning("PEB.Ldr is null");
            return nint.Zero;
        }

        Log.Debug("PEB=0x{Peb:X}, Ldr=0x{Ldr:X}", (ulong)pbi.PebBaseAddress, (ulong)ldr);

        // Allocate strings in remote process
        var dllNameWide = System.Text.Encoding.Unicode.GetBytes(dllName + "\0");
        var fullPathWide = System.Text.Encoding.Unicode.GetBytes(fullDllPath + "\0");

        var remoteDllName = MemoryHelpers.AllocateMemory(hProcess, (uint)dllNameWide.Length);
        var remoteFullPath = MemoryHelpers.AllocateMemory(hProcess, (uint)fullPathWide.Length);
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

        // Link into the three PEB module lists
        nint inLoadOrderListHead = ldr + 0x10;
        nint inMemoryOrderListHead = ldr + 0x20;
        nint inInitOrderListHead = ldr + 0x30;

        int inLoadOrderOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InLoadOrderLinks");
        int inMemoryOrderOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InMemoryOrderLinks");
        int inInitOrderOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("InInitializationOrderLinks");

        InsertTailList(hProcess, inLoadOrderListHead, remoteLdrEntry + inLoadOrderOffset);
        InsertTailList(hProcess, inMemoryOrderListHead, remoteLdrEntry + inMemoryOrderOffset);
        InsertTailList(hProcess, inInitOrderListHead, remoteLdrEntry + inInitOrderOffset);

        Log.Information("Module linked to PEB loader lists: {DllName}", dllName);
        return remoteLdrEntry;
    }

    /// <summary>
    /// Initializes CRT support for a manually mapped module.
    ///
    /// This performs two critical steps:
    /// 1. Links the module into PEB (so CRT can find it)
    /// 2. Calls LdrpHandleTlsData (to initialize Thread Local Storage)
    ///
    /// Without this, CRT DLLs will crash during initialization because:
    /// - CRT checks if the module is registered with the loader
    /// - CRT uses TLS for errno, thread state, etc.
    /// </summary>
    /// <returns>Address of LDR_DATA_TABLE_ENTRY, or Zero on failure.</returns>
    public static nint InitializeCrtModule(
        nint hProcess,
        int pid,
        nint moduleBase,
        uint sizeOfImage,
        nint entryPoint,
        ulong originalImageBase,
        string dllName)
    {
        // Generate a fake full path (looks legitimate)
        string fullPath = $"C:\\Windows\\System32\\{dllName}";

        // Step 1: Link module into PEB
        var remoteLdrEntry = LinkModuleToPEB(hProcess, pid, moduleBase, sizeOfImage,
            entryPoint, originalImageBase, dllName, fullPath);

        if (remoteLdrEntry == nint.Zero)
        {
            Log.Warning("Failed to link module to PEB");
            return nint.Zero;
        }

        // Step 2: Call LdrpHandleTlsData to initialize TLS
        var funcOffset = PatternScanner.FindLdrpHandleTlsDataOffset();
        if (funcOffset < 0)
        {
            Log.Warning("LdrpHandleTlsData not found - TLS may not work correctly");
            return remoteLdrEntry;
        }

        var remoteNtdll = ModuleHelpers.GetRemoteModuleHandle(hProcess, pid, "ntdll.dll");
        if (remoteNtdll == nint.Zero)
        {
            Log.Warning("Could not find ntdll.dll in remote process");
            return remoteLdrEntry;
        }

        var ldrpHandleTlsData = remoteNtdll + funcOffset;
        Log.Debug("Calling LdrpHandleTlsData at 0x{Addr:X} with entry at 0x{Entry:X}",
            (ulong)ldrpHandleTlsData, (ulong)remoteLdrEntry);

        // Allocate space for NTSTATUS result
        var remoteResult = MemoryHelpers.AllocateMemory(hProcess, 8);
        MemoryHelpers.WriteMemory(hProcess, remoteResult, BitConverter.GetBytes(0xDEADBEEFu));

        var stub = PatternScanner.BuildLdrpHandleTlsDataStub(
            (ulong)ldrpHandleTlsData, (ulong)remoteLdrEntry, (ulong)remoteResult);
        var remoteStub = MemoryHelpers.AllocateMemory(hProcess, (uint)stub.Length);

        try
        {
            MemoryHelpers.WriteMemory(hProcess, remoteStub, stub);
            MemoryHelpers.ProtectMemory(hProcess, remoteStub, (uint)stub.Length, Constants.PAGE_EXECUTE_READ);
            NativeMethods.FlushInstructionCache(hProcess, remoteStub, (uint)stub.Length);

            try
            {
                MemoryHelpers.CreateRemoteThreadAndWait(hProcess, remoteStub, nint.Zero, wait: true);

                // Read and log the result
                var resultBytes = MemoryHelpers.ReadMemory(hProcess, remoteResult, 4);
                uint ntstatus = BitConverter.ToUInt32(resultBytes);
                Log.Debug("LdrpHandleTlsData returned NTSTATUS: 0x{Status:X8}", ntstatus);

                if (ntstatus == 0)
                    Log.Debug("LdrpHandleTlsData executed successfully (STATUS_SUCCESS)");
                else
                    Log.Warning("LdrpHandleTlsData failed with NTSTATUS: 0x{Status:X8}", ntstatus);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to execute LdrpHandleTlsData stub");
            }

            // Verify TlsIndex was set
            int tlsIndexOffset = (int)Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("TlsIndex");
            var tlsIndexBytes = MemoryHelpers.ReadMemory(hProcess, remoteLdrEntry + tlsIndexOffset, 2);
            ushort tlsIndex = BitConverter.ToUInt16(tlsIndexBytes);
            Log.Debug("TLS initialization complete, TlsIndex = 0x{TlsIndex:X}", tlsIndex);
        }
        finally
        {
            MemoryHelpers.FreeMemory(hProcess, remoteStub);
            MemoryHelpers.FreeMemory(hProcess, remoteResult);
        }

        return remoteLdrEntry;
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

    /// <summary>
    /// Inserts an entry at the tail of a doubly-linked list.
    /// </summary>
    private static void InsertTailList(nint hProcess, nint listHead, nint entry)
    {
        var blinkBytes = MemoryHelpers.ReadMemory(hProcess, listHead + 8, 8);
        var prevEntry = (nint)BitConverter.ToInt64(blinkBytes);

        MemoryHelpers.WriteMemory(hProcess, entry, BitConverter.GetBytes((long)listHead));
        MemoryHelpers.WriteMemory(hProcess, entry + 8, BitConverter.GetBytes((long)prevEntry));
        MemoryHelpers.WriteMemory(hProcess, prevEntry, BitConverter.GetBytes((long)entry));
        MemoryHelpers.WriteMemory(hProcess, listHead + 8, BitConverter.GetBytes((long)entry));
    }

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
