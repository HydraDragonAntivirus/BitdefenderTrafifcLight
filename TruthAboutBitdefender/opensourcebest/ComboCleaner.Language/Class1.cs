using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace ComboCleaner.Language
{
    public static class DatabaseDumper
    {
        // P/Invoke signature to get the path of a loaded DLL.
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetModuleFileName(IntPtr hModule, System.Text.StringBuilder lpFilename, int nSize);

        /// <summary>
        /// This is the main entry point for the dumper.
        /// It MUST be called *after* bdcore.dll has been loaded into the process.
        /// </summary>
        /// <param name="bdCoreModuleHandle">The handle to the loaded bdcore.dll module.</param>
        public static void ExecuteDump(IntPtr bdCoreModuleHandle)
        {
            try
            {
                Console.WriteLine("[DATABASE DUMPER] Process initiated by host application.");

                if (bdCoreModuleHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[ERROR] Invalid module handle for bdcore.dll. Aborting.");
                    return;
                }

                // --- Find the Plugins directory relative to the loaded bdcore.dll ---
                System.Text.StringBuilder modulePathBuilder = new System.Text.StringBuilder(260);
                GetModuleFileName(bdCoreModuleHandle, modulePathBuilder, modulePathBuilder.Capacity);
                string bdCorePath = modulePathBuilder.ToString();

                if (string.IsNullOrEmpty(bdCorePath))
                {
                    Console.WriteLine("[ERROR] Could not resolve the path for bdcore.dll from its handle. Aborting.");
                    return;
                }

                string installPath = Path.GetDirectoryName(bdCorePath);
                string pluginsPath = Path.Combine(installPath, "Plugins");
                string outputFolder = @"C:\deobfuscated";

                Console.WriteLine($"[*] Located bdcore.dll at: {bdCorePath}");
                Console.WriteLine($"[*] Found Plugins folder: {pluginsPath}");
                Console.WriteLine($"[*] Output will be saved to: {outputFolder}");
                Directory.CreateDirectory(outputFolder);

                if (!Directory.Exists(pluginsPath))
                {
                    Console.WriteLine($"[ERROR] Plugins folder does not exist at the resolved path. Aborting.");
                    return;
                }

                Console.WriteLine(new string('-', 70));

                // --- Process all files in the Plugins directory ---
                ProcessFolder(pluginsPath, pluginsPath, outputFolder);

                Console.WriteLine(new string('-', 70));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[SUCCESS] Database dump complete.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[FATAL ERROR] An exception occurred during the dump: {ex.ToString()}");
                Console.ResetColor();
            }
        }

        private static void ProcessFolder(string rootInputPath, string currentPath, string rootOutputPath)
        {
            foreach (string filePath in Directory.GetFiles(currentPath))
            {
                ProcessSingleFile(filePath, rootInputPath, rootOutputPath);
            }
            foreach (string directoryPath in Directory.GetDirectories(currentPath))
            {
                ProcessFolder(rootInputPath, directoryPath, rootOutputPath);
            }
        }

        private static void ProcessSingleFile(string filePath, string baseInputPath, string baseOutputPath)
        {
            try
            {
                string relativePath = filePath.Substring(baseInputPath.Length + 1);
                string destinationPath = Path.Combine(baseOutputPath, relativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destinationPath));

                bool shouldDeobfuscate = false;
                string filenameLower = Path.GetFileName(filePath).ToLower();

                if (filenameLower.EndsWith(".cvd") || Regex.IsMatch(filenameLower, @"\.(?:\d{3}|[a-z]\d{2})$"))
                {
                    shouldDeobfuscate = true;
                }

                if (shouldDeobfuscate)
                {
                    Console.WriteLine($"  [DEOBFUSCATING] -> {relativePath}");
                    byte[] fileBytes = File.ReadAllBytes(filePath);
                    byte[] deobfuscatedBytes = DeobfuscateData(fileBytes);
                    File.WriteAllBytes(destinationPath + ".dec", deobfuscatedBytes);
                }
                else
                {
                    Console.WriteLine($"  [COPYING]       -> {relativePath}");
                    File.Copy(filePath, destinationPath, true);
                }
            }
            catch (Exception ex)
            {
                // Log silently to avoid cluttering output, or add verbose logging if needed.
            }
        }

        private static byte[] DeobfuscateData(byte[] data)
        {
            if (data == null || data.Length == 0) return new byte[0];
            byte key = 0xAA;
            for (int i = data.Length - 1; i >= 0; i--)
            {
                byte originalByte = data[i];
                data[i] ^= key;
                key = originalByte;
            }
            return data;
        }
    }
}
