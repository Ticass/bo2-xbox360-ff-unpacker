// XMem (LZX) compressor helper for the BO2 Xbox 360 fastfile repacker.
//
// Wraps Microsoft's XMemCompress, whose native implementation ships in the free
// XNA Game Studio 4.0 redistributable (XnaNative.dll, 32-bit). This is the same
// backend gibbed/XCompression uses. The public exports bake in a 64 KB window
// and 512 KB partition, so this helper binds gibbed's MD5-matched internal
// function addresses to request the 128 KB window used by BO2 fastfiles.
//
// Usage:  xmem_compress.exe <zone-input> <chunks-output> [chunkSizeHex] [nativeDir] [firstChunkSizeHex] [chunkPlanPath]
// The zone is split into fixed-size input chunks (default 0x8000), optionally
// with a different first chunk size or a newline-delimited hex chunk plan. Each chunk is
// compressed independently (fresh context = reset per chunk, exactly how the
// game's loader decompresses) and written to the output as a sequence of
// records: [uint32 little-endian compressedLen][compressedLen bytes]. The Python
// repacker reads these and applies the fastfile framing (vanilla windowing,
// Salsa20, header, zero suffix).
//
// Build: csc.exe /platform:x86 /optimize+ /out:_tools\xmem_compress.exe tools\xmem_compress.cs

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;

internal static class XMemCompress
{
    [StructLayout(LayoutKind.Sequential)]
    private struct CompressionSettings
    {
        public uint Flags;
        public uint WindowSize;
        public uint ChunkSize;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CreateCompressionContextDelegate(int type, ref CompressionSettings settings, int flags, ref IntPtr context);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CompressDelegate(IntPtr context, IntPtr output, ref int outputSize, IntPtr input, ref int inputSize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void DestroyCompressionContextDelegate(IntPtr context);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    private const int LzxCodec = 1;
    private const uint WindowSize = 128 * 1024;  // matches BO2 fastfiles / our decompressor
    private const int PreferredImageBase = 0x10000000;
    private const int CreateCompressionContextRva = 0x10197933 - PreferredImageBase;
    private const int CompressRva = 0x10197881 - PreferredImageBase;
    private const int DestroyCompressionContextRva = 0x1019790D - PreferredImageBase;
    private static CreateCompressionContextDelegate CreateCompressionContext;
    private static CompressDelegate Compress;
    private static DestroyCompressionContextDelegate DestroyCompressionContext;

    private static string ResolveNativeDir()
    {
        foreach (var view in new[] { @"SOFTWARE\WOW6432Node\Microsoft\XNA\Framework\v4.0", @"SOFTWARE\Microsoft\XNA\Framework\v4.0" })
        {
            var p = Registry.GetValue(@"HKEY_LOCAL_MACHINE\" + view, "NativeLibraryPath", null) as string;
            if (!string.IsNullOrEmpty(p) && File.Exists(Path.Combine(p, "XnaNative.dll")))
            {
                return p;
            }
        }
        return null;
    }

    private static T GetFunction<T>(ProcessModule module, int rva) where T : class
    {
        IntPtr address = IntPtr.Add(module.BaseAddress, rva);
        return (T)(object)Marshal.GetDelegateForFunctionPointer(address, typeof(T));
    }

    private static void LoadNativeFunctions(string nativeDir)
    {
        string nativePath = Path.Combine(nativeDir, "XnaNative.dll");
        IntPtr library = LoadLibrary(nativePath);
        if (library == IntPtr.Zero)
        {
            throw new Exception("LoadLibrary failed for " + nativePath + " (Win32 " + Marshal.GetLastWin32Error() + ")");
        }

        var module = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
            .FirstOrDefault(m => string.Equals(m.FileName, nativePath, StringComparison.OrdinalIgnoreCase));
        if (module == null)
        {
            throw new Exception("loaded XnaNative.dll but could not find its process module");
        }

        CreateCompressionContext = GetFunction<CreateCompressionContextDelegate>(module, CreateCompressionContextRva);
        Compress = GetFunction<CompressDelegate>(module, CompressRva);
        DestroyCompressionContext = GetFunction<DestroyCompressionContextDelegate>(module, DestroyCompressionContextRva);
    }

    private static byte[] CompressChunk(byte[] data, int offset, int length)
    {
        CompressionSettings settings;
        settings.Flags = 0;
        settings.WindowSize = WindowSize;
        settings.ChunkSize = (uint)length;

        IntPtr context = IntPtr.Zero;
        int hr = CreateCompressionContext(LzxCodec, ref settings, 1, ref context);
        if (hr != 0)
        {
            throw new Exception("CreateCompressionContext failed: 0x" + hr.ToString("X8"));
        }

        try
        {
            // Worst case (incompressible) needs a little headroom over the input.
            byte[] output = new byte[length + 0x4000];
            GCHandle inHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            GCHandle outHandle = GCHandle.Alloc(output, GCHandleType.Pinned);
            int outputSize = output.Length;
            int inputSize = length;
            try
            {
                hr = Compress(context, outHandle.AddrOfPinnedObject(), ref outputSize,
                              IntPtr.Add(inHandle.AddrOfPinnedObject(), offset), ref inputSize);
                if (hr == 0 && outputSize == 0)
                {
                    inputSize = 0;
                    outputSize = output.Length;
                    hr = Compress(context, outHandle.AddrOfPinnedObject(), ref outputSize,
                                  IntPtr.Zero, ref inputSize);
                }
            }
            finally
            {
                inHandle.Free();
                outHandle.Free();
            }
            if (hr != 0)
            {
                throw new Exception("Compress failed: 0x" + hr.ToString("X8"));
            }
            byte[] result = new byte[outputSize];
            Array.Copy(output, result, outputSize);
            return result;
        }
        finally
        {
            DestroyCompressionContext(context);
        }
    }

    private static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: xmem_compress.exe <zone-input> <chunks-output> [chunkSizeHex] [nativeDir] [firstChunkSizeHex] [chunkPlanPath]");
            return 2;
        }

        int chunkSize = 0x8000;
        if (args.Length >= 3 && !string.IsNullOrEmpty(args[2]))
        {
            chunkSize = Convert.ToInt32(args[2], 16);
        }

        int firstChunkSize = chunkSize;
        if (args.Length >= 5 && !string.IsNullOrEmpty(args[4]))
        {
            firstChunkSize = Convert.ToInt32(args[4], 16);
        }

        List<int> chunkPlan = null;
        if (args.Length >= 6 && !string.IsNullOrEmpty(args[5]))
        {
            chunkPlan = new List<int>();
            foreach (string rawLine in File.ReadAllLines(args[5]))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#"))
                {
                    continue;
                }
                chunkPlan.Add(Convert.ToInt32(line, 16));
            }
        }

        string nativeDir = args.Length >= 4 && !string.IsNullOrEmpty(args[3]) ? args[3] : ResolveNativeDir();
        if (string.IsNullOrEmpty(nativeDir))
        {
            Console.Error.WriteLine("error: could not locate XnaNative.dll (install XNA Game Studio 4.0 redistributable)");
            return 3;
        }
        SetDllDirectory(nativeDir);

        try
        {
            LoadNativeFunctions(nativeDir);
            byte[] zone = File.ReadAllBytes(args[0]);
            using (var outStream = new FileStream(args[1], FileMode.Create, FileAccess.Write))
            using (var writer = new BinaryWriter(outStream))
            {
                int chunks = 0;
                for (int pos = 0; pos < zone.Length;)
                {
                    int wanted = chunkPlan != null && chunks < chunkPlan.Count
                        ? chunkPlan[chunks]
                        : (chunks == 0 ? firstChunkSize : chunkSize);
                    int len = Math.Min(wanted, zone.Length - pos);
                    byte[] compressed = CompressChunk(zone, pos, len);
                    writer.Write((uint)compressed.Length);
                    writer.Write(compressed);
                    chunks++;
                    pos += len;
                }
                Console.Error.WriteLine("compressed " + chunks + " chunk(s) from " + zone.Length + " zone bytes");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 1;
        }
        return 0;
    }
}
