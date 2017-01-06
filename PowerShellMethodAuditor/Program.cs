using System;
using O365.Security.ETW;

namespace PowerShellMethodAuditor
{
    class Program
    {
        static void Main(string[] args)
        {
            var trace = new UserTrace();

            // The name of the PowerShell provider that gives us with detailed
            // method execution logging is "Microsoft-Windows-PowerShell".
            //
            // If you want to explore all the events in this provider,
            // you'll need to use Message Analyzer to load the trace and explore
            // the events.
            //
            // Download: https://www.microsoft.com/en-us/download/details.aspx?id=44226
            var powershellProvider = new Provider("Microsoft-Windows-PowerShell");

            var powershellFilter = new EventFilter(
                Filter.EventIdIs(7937)
                .And(UnicodeString.Contains("Payload", "Started")));

            powershellFilter.OnEvent += OnEvent;

            // The "Any" and "All" flags can be sussed out using Microsoft Message Analyzer.
            powershellProvider.Any = 0x20;
            powershellProvider.AddFilter(powershellFilter);

            trace.Enable(powershellProvider);

            Console.CancelKeyPress += (sender, eventArg) =>
            {
                if (trace != null)
                {
                    trace.Stop();
                }
            };

            // This is a blocking call. Ctrl-C to stop.
            trace.Start();
        }

        // These represent strings in the 7937 ContextInfo payload.
        // They're always in this format, with each key/value pair separated
        // by a \n\r. For more information, use Message Analyzer to look
        // at the 7937 event structure.
        private const string HostAppKey = "Host Application = ";
        private const string CmdNameKey = "Command Name = ";
        private const string CmdTypeKey = "Command Type = ";
        private const string UserNameKey = "User = ";

        /// <summary>
        /// Event 7937's payload is basically a big well-formatted string.
        /// We have to parse it by hand, breaking out the interesting bits.
        /// Fortunately, interesting bits are separated by \n\r so we can break
        /// up the parsing by line.
        /// </summary>
        /// <param name="record"></param>
        static void OnEvent(IEventRecord record)
        {
            string data = string.Empty;
            if (!record.TryGetUnicodeString("ContextInfo", out data))
            {
                Console.WriteLine("Could not parse 'ContextInfo' from PowerShell event");
                return;
            }

            var startIndex = 0;

            // The order these keys are parsed in is static. There is no
            // guarantee, however, that future Windows versions won't change
            // the order. This is confirmed to work in:
            //  - Windows 10
            //  - Windows Server 2016
            //  - Windows 8.1
            //  - Windows Server 2012 R2
            var index = data.IndexOf(HostAppKey, startIndex);
            var host = index != -1
                        ? ReadToNewline(data, index + HostAppKey.Length, out startIndex)
                        : string.Empty;

            index = data.IndexOf(CmdNameKey, startIndex);
            var name = index != -1
                        ? ReadToNewline(data, index + CmdNameKey.Length, out startIndex)
                        : string.Empty;

            index = data.IndexOf(CmdTypeKey, startIndex);
            var type = index != -1
                        ? ReadToNewline(data, index + CmdTypeKey.Length, out startIndex)
                        : string.Empty;

            index = data.IndexOf(UserNameKey, startIndex);
            var user = index != -1
                        ? ReadToNewline(data, index + UserNameKey.Length, out startIndex)
                        : string.Empty;

            Console.WriteLine($"user: {user} - {host} invoked PowerShell method '{name}' (type: {type})");
        }

        public static string ReadToNewline(string data, int index, out int newIndex)
        {
            if (index >= data.Length)
            {
                newIndex = index;
                return string.Empty;
            }

            if (index < 0) index = 0;

            var start = index;

            while (index < data.Length && data[index] != '\r') index++;

            newIndex = index;
            return data.Substring(start, index - start);
        }
    }
}
