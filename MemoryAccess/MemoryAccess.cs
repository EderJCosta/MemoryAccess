using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MemoryAccess
{
    public class MemoryAccessAPI
    {
        private const int INVALID_HANDLE_VALUE = -1;
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
        ProcessAccessFlags processAccess,
        bool bInheritHandle,
        int processId
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct MODULEENTRY32
        {
            internal uint dwSize;
            internal uint th32ModuleID;
            internal uint th32ProcessID;
            internal uint GlblcntUsage;
            internal uint ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [MarshalAs(UnmanagedType.AsAny)] Object lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll")]
        static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, int th32ProcessID);

        /// <summary>
        /// Returns the base address of a Module.
        /// </summary>
        public static IntPtr GetModuleBaseAddress(Process process, string moduleName)
        {
            IntPtr address = IntPtr.Zero;

            foreach (ProcessModule m in process.Modules)
            {
                if (m.ModuleName == moduleName)
                {
                    address = m.BaseAddress;
                    break;
                }
            }
            return address;
        }

        /// <summary>
        /// Returns the base address of a Module.
        /// </summary>
        public static IntPtr GetModuleBaseAddress(int processId, string moduleName)
        {
            IntPtr address = IntPtr.Zero;
            IntPtr snapshotAddress = CreateToolhelp32Snapshot(SnapshotFlags.Module | SnapshotFlags.Module32, processId);

            if (snapshotAddress.ToInt64() != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32 modEntry = new MODULEENTRY32();
                modEntry.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

                if (Module32First(snapshotAddress, ref modEntry))
                {
                    do
                    {
                        if (modEntry.szModule.Equals(moduleName))
                        {
                            address = modEntry.modBaseAddr;
                            break;
                        }
                    } while (Module32Next(snapshotAddress, ref modEntry));
                }

            }
            CloseHandle(snapshotAddress);
            return address;
        }

        /// <summary>
        /// Add offsets to pointer and return the Address
        /// </summary>
        public static IntPtr GetMemoryAddress(IntPtr handleProcess, IntPtr pointer, int[] offsets)
        {
            var buffer = new byte[IntPtr.Size];
            foreach (int i in offsets)
            {
                ReadProcessMemory(handleProcess, pointer, buffer, buffer.Length, out var read);
                pointer = (IntPtr.Size == 4)
                    ? IntPtr.Add(new IntPtr(BitConverter.ToInt32(buffer, 0)), i)
                    : IntPtr.Add(new IntPtr(BitConverter.ToInt64(buffer, 0)), i);
            }
            return pointer;
        }

        /// <summary>
        /// Return the address value(int)
        /// </summary>
        public static int GetAddressIntegerValue(IntPtr handleProcess, IntPtr address, int bufferLength)
        {
            byte[] buffer = new byte[bufferLength];
            MemoryAccessAPI.ReadProcessMemory(handleProcess, address, buffer, bufferLength, out var read);
            return BitConverter.ToInt32(buffer, 0);
        }

        /// <summary>
        /// Return the address value(bytes)
        /// </summary>
        public static byte[] GetAddressBytesValue(IntPtr handleProcess, IntPtr address, int bufferLength)
        {
            byte[] buffer = new byte[bufferLength];
            MemoryAccessAPI.ReadProcessMemory(handleProcess, address, buffer, bufferLength, out var read);
            return buffer;
        }

        public static IntPtr ScanArrayOfBytes(Process process, String pattern)
        {
            byte[] modulebytes = new byte[process.MainModule.ModuleMemorySize];
            byte[] convertedByteArray = ConvertPatternToBytes(pattern);
            ReadProcessMemory(process.Handle, process.MainModule.BaseAddress, modulebytes, process.MainModule.ModuleMemorySize, out var bytesRead);
            IntPtr address = IntPtr.Zero;
            for (int i = 0; i < modulebytes.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < convertedByteArray.Length && i + j < modulebytes.Length; j++)
                {
                    if (convertedByteArray[j] == 0x0)
                    {
                        continue;
                    }
                    if (convertedByteArray[j] != modulebytes[i + j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    address = process.MainModule.BaseAddress + i;
                }
            }
            return address;
        }

        public static bool WriteBytes(IntPtr handleProcess, IntPtr addressToWrite, String pattern)
        {
            byte[] bytes = ConvertPatternToBytes(pattern);
            WriteProcessMemory(handleProcess, addressToWrite, bytes, bytes.Length, out IntPtr bytesWritten);
            return bytesWritten == IntPtr.Zero ? false : true;
        }


        private static byte[] ConvertPatternToBytes(String pattern)
        {
            String[] patternBytes = pattern.Split(' ');
            byte[] convertertedArray = new byte[patternBytes.Length];
            for (int i = 0; i < patternBytes.Length; i++)
            {
                convertertedArray[i] = patternBytes[i] == "??" ? Convert.ToByte("0", 16) : Convert.ToByte(patternBytes[i], 16);
            }
            return convertertedArray;
        }

    }
}
