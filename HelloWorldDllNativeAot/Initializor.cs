using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HelloWorldDllNativeAot;

public static partial class Initializor
{
    [LibraryImport("user32.dll", EntryPoint = "MessageBoxA", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int MessageBoxA(nint hWnd, string lpText, string lpCaption, uint uType);

    private const uint MB_OK = 0x00000000;


    [ModuleInitializer]
    public static void Initialize()
    {
        MessageBoxA(0, "Initializor: Initialize", "Hello", MB_OK);
    }
}
