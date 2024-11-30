using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.IO;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;

namespace CheckDrivers
{
    internal class Program
    {
        public static bool edrfound = false;
        public static bool vulndrv = false;
        public static bool download = false;
        public static bool drvlist = false;
        public static bool edrcheck = false;
        public static bool compare = false;

        [DllImport("psapi")]
        static extern bool EnumDeviceDrivers([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] ddAddresses, UInt32 arraySizeBytes, [MarshalAs(UnmanagedType.U4)] out UInt32 bytesNeeded);

        [DllImport("psapi")]
        private static extern int GetDeviceDriverFileNameA(IntPtr ddAddress, System.Text.StringBuilder ddBaseName, int baseNameStringSizeChars);

        public class JSONDrivers
        {
            public List<KnownVulnerableSamples> KnownVulnerableSamples { get; set; }

        }

        [JsonObject(MemberSerialization = MemberSerialization.OptIn)]
        public class KnownVulnerableSamples
        {
            [JsonProperty(PropertyName = "Filename")]
            public string Filename { get; set; }

            [JsonProperty(PropertyName = "SHA256")]
            public string SHA256 { get; set; }
        }

        private static string GetChecksum(string file)
        {
            using (FileStream stream = File.OpenRead(file))
            {
                var sha = new SHA256Managed();
                byte[] b = sha.ComputeHash(stream);
                string CheckSum = BitConverter.ToString(b).Replace("-", String.Empty);
                return CheckSum;
            }
        }

        static void ResetValues()
        {
            edrfound = false;
            vulndrv = false;
            download = false;
            drvlist = false;
            edrcheck = false;
            compare = false;
        }
        static void Help()
        {
            Console.WriteLine(@"" +
                "1. --help, -h - Display help" +
                "2. --dl - Download drivers.json from loldrivers.io\n" +
                "3. --list - Use EnumDeviceDrivers to list current drivers\n" +
                "4. --compare - Compare current drivers with loldrivers.io drivers list\n" +
                "5. --edr - Check if current drivers correspond to known EDR drivers\n" +
                "");
            return;
        }

        static void AttemptDownload()
        {

            string uri = "https://www.loldrivers.io/api/drivers.json";
            string filePath = "drivers.json";

            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls
                                                    | System.Net.SecurityProtocolType.Tls11
                                                    | System.Net.SecurityProtocolType.Tls12;

            using (System.Net.WebClient wc = new System.Net.WebClient())
            {

                // Subscribe to the DownloadFileCompleted event
                wc.DownloadFileCompleted += (sender, e) =>
                {
                    if (e.Error != null)
                    {
                        Console.WriteLine($"[!] Download failed: {e.Error.Message}");
                    }
                    else if (e.Cancelled)
                    {
                        Console.WriteLine("[!] Download canceled.");
                    }
                    else
                    {
                        Console.WriteLine("[+] drivers.json file downloaded successfully.");
                        Console.WriteLine("Press any key to exit.");
                        
                    }
                };

                try
                {
                    // Start the asynchronous download
                    wc.DownloadFileAsync(new Uri(uri), filePath);
                    Console.WriteLine("Downloading... Press any key to cancel.");
                    Console.ReadKey(); // Prevents the application from exiting immediately
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] An error occurred: {ex.Message}");
                }
            }

        }
        static void Main(string[] args)
        {

            List<string> edrdrv = new List<string> { "tbimdsa.sys", "TMEBC64.sys", "tmeyes.sys", "cyvrlpc.sys", "egfilterk.sys", "atc.sys", "vlflt.sys", "csacentr.sys", "csaenh.sys", "csareg.sys", "csascr.sys", "csaav.sys", "csaam.sys", "esensor.sys", "fsgk.sys", "fsatp.sys", "fshs.sys", "eaw.sys", "im.sys", "csagent.sys", "rvsavd.sys", "dgdmk.sys", "atrsdfw.sys", "mbamwatchdog.sys", "edevmon.sys", "SentinelMonitor.sys", "edrsensor.sys", "ehdrv.sys", "HexisFSMonitor.sys", "CyOptics.sys", "CarbonBlackK.sys", "CyProtectDrv32.sys", "CyProtectDrv64.sys", "CRExecPrev.sys", "ssfmonm.sys", "CybKernelTracker.sys", "SAVOnAccess.sys", "savonaccess.sys", "sld.sys", "aswSP.sys", "FeKern.sys", "klifks.sys", "klifaa.sys", "Klifsm.sys", "mfeaskm.sys", "mfencfilter.sys", "WFP_MRT.sys", "groundling32.sys", "SAFE-Agent.sys", "groundling64.sys", "avgtpx86.sys", "avgtpx64.sys", "pgpwdefs.sys", "GEProtection.sys", "diflt.sys", "sysMon.sys", "ssrfsf.sys", "emxdrv2.sys", "reghook.sys", "spbbcdrv.sys", "bhdrvx86.sys", "bhdrvx64.sys", "SISIPSFileFilter.sys", "symevent.sys", "VirtualAgent.sys", "vxfsrep.sys", "VirtFile.sys", "SymAFR.sys", "symefasi.sys", "symefa.sys", "symefa64.sys", "SymHsm.sys", "evmf.sys", "GEFCMP.sys", "VFSEnc.sys", "pgpfs.sys", "fencry.sys", "symrg.sys", "cfrmd.sys", "cmdccav.sys", "cmdguard.sys", "CmdMnEfs.sys", "MyDLPMF.sys", "PSINPROC.SYS", "PSINFILE.SYS", "amfsm.sys", "amm8660.sys", "amm6460.sys" };
            List<string> founddrv = new List<string>();
            List<string> sha256sum = new List<string>();
            System.Text.StringBuilder sb = new System.Text.StringBuilder(1000);
            uint bytesNeeded = 0;
            Boolean running = true;
            bool activeGUI = true;
            Console.WriteLine(@"     ____ _               _    ____       _                 ____ _   _ ___          _ " + "\n" +
                              @"    / ___| |__   ___  ___| | _|  _ \ _ __(_)_   _____ _ __ / ___| | | |_ _| __   __/ |" + "\n" +
                              @"   | |   | '_ \ / _ \/ __| |/ / | | | '__| \ \ / / _ \ '__| |  _| | | || |  \ \ / /| |" + "\n" +
                              @"   | |___| | | |  __/ (__|   <| |_| | |  | |\ V /  __/ |  | |_| | |_| || |   \ V / | |" + "\n" +
                              @"    \____|_| |_|\___|\___|_|\_\____/|_|  |_| \_/ \___|_|   \____|\___/|___|   \_/  |_|" + "\n");
            foreach (string arg in args)
            {
                if (args.Length > 0)
                {
                    if (arg.Equals("--help"))
                    {
                        Help();
                        return;
                    }
                    if (arg.Equals("--dl"))
                    {
                        download = true;
                    }
                    if (arg.Equals("--list"))
                    {
                        drvlist = true;
                    }
                    if (arg.Equals("--edr"))
                    {
                        edrcheck = true;
                    }
                    if (arg.Equals("--compare"))
                    {
                        compare = true;
                    }
                    activeGUI = false;
                }
            }


            do
            {
                if (activeGUI)
                {


                    Console.WriteLine(
                        "\n1. Help\n" +
                        "2. Download drivers.json from loldrivers.io\n" +
                        "3. Use EnumDeviceDrivers to list current drivers\n" +
                        "4. Compare current drivers with loldrivers.io drivers list\n" +
                        "5. Check if current drivers correspond to known EDR drivers\n" +
                        "0. Exit Program\n");
                    Console.Write("Enter a Digit: ");
                    int userInput = Convert.ToInt32(Console.ReadLine());
                    while (userInput == null || userInput < 0 || userInput > 5)
                    {
                        Console.WriteLine("Please enter a choice between 0-5");
                        userInput = Convert.ToInt32(Console.ReadLine());
                        if (userInput >= 0 && userInput <= 5)
                        {
                            break;
                        }
                    }
                    switch (userInput)
                    {
                        case 0:
                            Console.WriteLine("Exiting Program");
                            running = false;
                            return;
                        case 1:
                            Help();
                            break;
                        case 2:
                            download = true;
                            break;
                        case 3:
                            drvlist = true;
                            break;
                        case 4:
                            edrcheck = true;
                            break;
                        case 5:
                            compare = true;
                            break;
                        default:
                            Console.WriteLine("Invalid Choice");
                            break;

                    }
                }



                if (EnumDeviceDrivers(null, 0, out bytesNeeded))
                {
                    UInt32 arraySize = bytesNeeded / (uint)IntPtr.Size;
                    UInt32 arraySizeBytes = bytesNeeded;
                    IntPtr[] ddAddresses = new IntPtr[arraySize];
                    List<long> list = new List<long>();
                    string diskpath = "";
                    EnumDeviceDrivers(ddAddresses, arraySizeBytes, out bytesNeeded);

                    for (int i = 0; i < arraySize - 1; i++)
                    {
                        diskpath = "";
                        sb.Clear();
                        if (GetDeviceDriverFileNameA(ddAddresses[i], sb, sb.Capacity) > 0)
                        {

                            if (sb.ToString().Contains("\\SystemRoot\\"))
                            {
                                diskpath = sb.ToString().Replace("\\SystemRoot\\", "\\Windows\\");
                                founddrv.Add(diskpath);
                            }
                            if (sb.ToString().Contains("\\??\\"))
                            {
                                diskpath = sb.ToString().Replace("\\??\\", "");
                                founddrv.Add(diskpath);
                            }
                        }
                    }
                }


                if (drvlist)
                {
                    Console.WriteLine("[-] Listing running drivers..");
                    string certname = "";
                    foreach (string drv in founddrv)
                    {
                        try
                        {
                            string cert = X509Certificate.CreateFromSignedFile(drv).GetName();
                            var m = Regex.Match(cert, @".*O=(.*?), .*");
                            certname = m.Groups[1].Value.Replace('"', ' ');
                        }
                        catch
                        {
                            continue;
                        }

                        Console.WriteLine(drv + " (" + certname + ")");
                    }

                }
                if (download)
                {
                    AttemptDownload();
                }

                if (compare)
                {
                    Console.WriteLine("[-] Check for vuln drivers from loldrivers.io..");

                    if (!File.Exists("./drivers.json"))
                    {
                        AttemptDownload();
                    }

                    List<JSONDrivers> drvobj = null;
                    try
                    {
                        drvobj = JsonConvert.DeserializeObject<List<JSONDrivers>>(File.ReadAllText("drivers.json"));
                    }
                    catch (FileNotFoundException)
                    {
                        Console.WriteLine("[!] drivers.json file not found! try with --dl");
                        return;
                    }

                    List<string> tmp = new List<string>();
                    foreach (JSONDrivers drv in drvobj)
                    {
                        foreach (KnownVulnerableSamples item in drv.KnownVulnerableSamples)
                        {
                            if (item.SHA256 != null)
                                tmp.Add(item.SHA256);
                        }
                    }

                    sha256sum = tmp.Distinct().ToList();
                    if (sha256sum.Count > 0 && founddrv.Count > 0)
                    {
                        Console.WriteLine("\nChecking for vuln driver SHA256 checksum..");
                        foreach (string drv in founddrv)
                        {
                            // drv cannot be changed since its the iterator
                            String tmpDrv = drv;
                            if (drv.EndsWith(".sys"))
                            {
                                try
                                {
                                    // Adds C: to search in the correct drivers in the window Windows incase if program is running in another drive
                                    // for example E: D: F
                                    if (drv.StartsWith("\\"))
                                    {
                                        tmpDrv = "C:" + drv;
                                    }
                                    string CS = GetChecksum(tmpDrv);
                                    if (sha256sum.Contains(CS))
                                    {
                                        vulndrv = true;
                                        Console.WriteLine($"[+] FOUND VULNERABLE DRIVER : {tmpDrv} ({CS})");
                                    }
                                }
                                catch (FileNotFoundException)
                                {
                                    Console.WriteLine("File not found " + tmpDrv);
                                    continue;
                                }
                                catch (UnauthorizedAccessException)
                                {
                                    Console.WriteLine("File access denied " + tmpDrv);
                                    continue;
                                }
                            }

                        }

                        if (!vulndrv)
                        {
                            Console.WriteLine("[+] No known vulnerable driver found.");
                        }
                    }
                }


                if (edrcheck)
                {
                    Console.WriteLine("[-] Checking for known EDR drivers..");
                    foreach (string drv in founddrv)
                    {
                        string drvbasename = drv.Split('\\').Last();

                        if (edrdrv.Any(x => x.Equals(drvbasename, StringComparison.OrdinalIgnoreCase)))
                        {
                            edrfound = true;

                            if ("tbimdsa.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "tmeyes.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "TMEBC64.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("TrendMicro drivers Found! (" + drvbasename + ")");
                            }
                            if ("cyvrlpc.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Cortex XDR Found! (" + drvbasename + ")");
                            }
                            if ("FeKern.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "WFP_MRT.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("FireEye Found! (" + drvbasename + ")");
                            }
                            if ("eaw.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Raytheon Cyber Solutions Found! (" + drvbasename + ")");
                            }
                            if ("rvsavd.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("CJSC Returnil Software Found! (" + drvbasename + ")");
                            }
                            if ("dgdmk.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Verdasys Inc. Found! (" + drvbasename + ")");
                            }
                            if ("atrsdfw.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Altiris (Symantec) Found! (" + drvbasename + ")");
                            }
                            if ("mbamwatchdog.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Malwarebytes Found! (" + drvbasename + ")");
                            }
                            if ("edevmon.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "ehdrv.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("ESET Found! (" + drvbasename + ")");
                            }
                            if ("SentinelMonitor.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("SentinelOne Found! (" + drvbasename + ")");
                            }
                            if ("edrsensor.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("BitDefender SRL Found! (" + drvbasename + ")");
                            }
                            if ("atc.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "egfilterk.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "vlflt.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("TEHTRIS XDR Found! (" + drvbasename + ")");
                            }
                            if ("HexisFSMonitor.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Hexis Cyber Solutions Found! (" + drvbasename + ")");
                            }
                            if ("CyOptics.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "CyProtectDrv32.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "CyProtectDrv64.sys.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Cylance Inc. Found! (" + drvbasename + ")");
                            }
                            if ("aswSP.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Avast Found! (" + drvbasename + ")");
                            }
                            if ("mfeaskm.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "mfencfilter.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("McAfee Found! (" + drvbasename + ")");
                            }
                            if ("groundling32.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "groundling64.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Dell Secureworks Found! (" + drvbasename + ")");
                            }
                            if ("avgtpx86.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "avgtpx64.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("AVG Technologies Found! (" + drvbasename + ")");
                            }
                            if ("pgpwdefs.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "GEProtection.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "diflt.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "sysMon.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "ssrfsf.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "emxdrv2.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "reghook.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "spbbcdrv.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "bhdrvx86.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "bhdrvx64.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "SISIPSFileFilter".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "symevent.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "vxfsrep.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "VirtFile.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "SymAFR.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "symefasi.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "symefa.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "symefa64.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "SymHsm.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "evmf.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "GEFCMP.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "VFSEnc.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "pgpfs.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "fencry.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "symrg.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Symantec Found! (" + drvbasename + ")");
                            }
                            if ("SAFE-Agent.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("SAFE-Cyberdefense Found! (" + drvbasename + ")");
                            }
                            if ("CybKernelTracker.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("CyberArk Software Found! (" + drvbasename + ")");
                            }
                            if ("klifks.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "klifaa.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "Klifsm.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Kaspersky Found! (" + drvbasename + ")");
                            }
                            if ("SAVOnAccess.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "savonaccess.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "sld.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Sophos Found! (" + drvbasename + ")");
                            }
                            if ("ssfmonm.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Webroot Software, Inc. Found! (" + drvbasename + ")");
                            }
                            if ("CarbonBlackK.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Carbon Black Found! (" + drvbasename + ")");
                            }
                            if ("CRExecPrev.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Cybereason Found! (" + drvbasename + ")");
                            }
                            if ("im.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "csagent.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("CrowdStrike Found! (" + drvbasename + ")");
                            }
                            if ("cfrmd.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "cmdccav.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "cmdguard.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "CmdMnEfs.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "MyDLPMF.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Comodo Security Solutions Found! (" + drvbasename + ")");
                            }
                            if ("PSINPROC.SYS".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "PSINFILE.SYS".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "amfsm.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "amm8660.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "amm6460.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Panda Security Found! (" + drvbasename + ")");
                            }
                            if ("fsgk.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "fsatp.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "fshs.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("F-Secure Found! (" + drvbasename + ")");
                            }
                            if ("esensor.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Endgame Found! (" + drvbasename + ")");
                            }
                            if ("csacentr.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "csaenh.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "csareg.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "csascr.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "csaav.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase) || "csaam.sys".Equals(drvbasename, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine("Cisco Found! (" + drvbasename + ")");
                            }
                        }
                    }

                    if (!edrfound)
                    {
                        Console.WriteLine("[+] No EDR driver Found!");
                    }
                }
                ResetValues();
                if(args.Length > 0)
                {
                    running = false;
                }
            } while (running);

            return;
        }
    }
}
