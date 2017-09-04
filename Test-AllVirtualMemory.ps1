<#

.SYNOPSIS

Get Hash values from process memory.  This script will remotly scan the CODE virtual memory of the target system
and perform SHA256 hash against each PAGE of memory.  It identifies shared code pages and only scan's shared pages
1 time.  This help's the performance (at least 1/2 the pages should be shared).

It then send's sufficent information to a cloud box that queries a hash database and applies some de-locating
so that it can match the pages hash values properly (a few more cases here).

There will be NO false positives, only false negatives.  So you may be told something is NOT safe when it is.
Hopefully this isn't too often.

Only expect Microsoft binaries to be in the hash database, I don't have you're software ;)

This is an experamental server in Azure, if it get's expensive I'm going to have to shut it down or ask somebody to pay for it.

I may just hand out the server code so you can host you're own.

This script is not that fast right now and takes a while to run. But it should detect anybody using any sort of reflective DLL 
injection (again if we have the software, so like if they use OLE32.dll or whatever to inject into this will find them). 

We have a few trillion hashes in the server, it's very big.  The cache is only 5GB though so if it get's polluted I have to empty 
it manually right now. Anyhow that's my problem ;)

.EXAMPLE

I currently get scan arguments from the environment since they are passwords etc..
This is a very early version still some rough edges

PS > .\Test-AllVirtualMemory.ps1

Way below the 3 environment variables to set are;

REMOTE_HOST (target to scan)
USER_NAME (a user that has admin on the target)
PASS_WORD (that user's password)

$serverName = [Environment]::GetEnvironmentVariable("REMOTE_HOST")
$username = [Environment]::GetEnvironmentVariable("USER_NAME")
$password = [Environment]::GetEnvironmentVariable("PASS_WORD")

#>

$block =
{
	Set-StrictMode -Version 3
	try
	{
		$nm = New-Object MemTest+NativeMethods
	}
	catch
	{
				
	$Code = @"
		using System;
		using System.Collections.Generic;
		using System.Diagnostics;
		using System.Linq;
		using System.Runtime.InteropServices;
		using System.Text;
		using System.Security.Cryptography;
		using System.IO;

		namespace MemTest
		{
		    public class MemPageHash
		    {
		        public string HdrHash;
		        public uint TimeDateStamp;
		        public long AllocationBase;
		        public long BaseAddress;
		        public long Size;
		        public uint ImageSize;
		        public int Id;
		        public string ProcessName;
		        public string ModuleName;
		        public int SharedAway;
		        public int HashedBlocks;
		        public HashSet<PageHashBlock> HashSet = new HashSet<PageHashBlock>();
		    }

		    public class PageHashBlock
		    {
		        public long Address;
		        public string Hash;
		    }

		    
		    public class PageHashBlockResult
		    {
		        public long Address;
		        public bool HashCheckEquivalant;
		    }

		    public struct MiniSection
		    {
		        public string Name;
		        public uint VirtualSize; // size in memory
		        public uint VirtualAddress; // offset to section base in memory (from ImageBase)
		        public uint RawFileSize; // size on disk
		        public uint RawFilePointer; // offset to section base on disk (from 0)
		        public bool IsExec { get { return (Characteristics & 0x20000000) != 0; } }
		        public bool IsCode { get { return (Characteristics & 0x20000000) != 0; } }
		        public bool IsRead { get { return (Characteristics & 0x40000000) != 0; } }
		        public bool IsWrite { get { return (Characteristics & 0x80000000) != 0; } }
		        public bool IsShared { get { return (Characteristics & 0x10000000) != 0; } }
		        public bool IsDiscard { get { return (Characteristics & 0x02000000) != 0; } }
		        public uint Characteristics;

		        public static MiniSection Empty;

		        static MiniSection()
		        {
		            Empty.Name = string.Empty;
		            Empty.Characteristics = 0;
		            Empty.VirtualAddress = 0;
		            Empty.RawFilePointer = 0;
		            Empty.VirtualSize = 0;
		            Empty.RawFileSize = 0;
		        }

		        public override string ToString()
		        {
		            return String.Format("{0} - VBase {1:X}:{VirtualSize:X} - File {2:X}:{3:X} - R:{4},W:{5},X:{6},S:{7},D:{8}",
		                Name, VirtualAddress, RawFilePointer, RawFileSize, IsRead, IsWrite, IsExec, IsShared, IsDiscard);
		        }
		    }
		    // Extract compiles a local reloc set that can be used when dumping memory to recover identical files 
		    public class Extract
		    {
		        public int rID;
		        public long VA;
		        public static int NewCnt;
		        public static int Verbose;
		        public static bool OverWrite;
		        public string Hash;
		        public string FileName;
		        public uint RelocPos;
		        public uint RelocSize;
		        public uint ImportDirPos;
		        public uint ImportDirSize;
		        public uint DebugDirPos;
		        public uint DebugDirSize;
		        public uint ClrAddress;
		        public uint ClrSize;
		        public uint EntryPoint;
		        public uint BaseOfCode;
		        public ulong ImageBase;
		        public long ImageBaseOffset;
		        public uint TimeStamp;
		        public bool Is64;
		        public uint SectionAlignment;
		        public uint FileAlignment;
		        public uint SizeOfImage;
		        public uint SizeOfHeaders;
		        public short NumberOfSections;
		        public bool IsCLR;
		        // maybe ordered list would emit better errors for people
		        public List<MiniSection> Sections;
		        int secOff;
		        public override string ToString()
		        {
		            StringBuilder sb = new StringBuilder(String.Format("{0}**PE FILE** \t-\t-\t Date   [{1:X8}]{2}*DebugPos* \t-\t-\t Offset [{3:X8}] \t-\t Size [{4:X8}] {5}*Base*  \t-\t-\t Offset [{6:X16}] -\t Size [{7:X8}]{8}",
		                Environment.NewLine, TimeStamp, Environment.NewLine, DebugDirPos, DebugDirSize, Environment.NewLine, ImageBase, SizeOfImage, Environment.NewLine));
		            foreach (var s in Sections)
		                sb.Append(String.Format("[{0}] \t-\t-\t Offset [{1:X8}] \t-\t Size [{2:X8}]{3}",
		                    s.Name.PadRight(8), s.VirtualAddress, s.VirtualSize, Environment.NewLine));

		            sb.AppendLine();
		            return sb.ToString();
		        }

		        public static Extract IsBlockaPE(byte[] block, int blockOffset = 0)
		        {
		            Extract extracted_struct = new Extract();

		            if (block[blockOffset] != 0x4d || block[blockOffset + 1] != 0x5a)
		                return null;

		            var headerOffset = BitConverter.ToInt32(block, blockOffset + 0x3C);

		            // bad probably
		            if (headerOffset > 3000)
		                return null;

		            if (BitConverter.ToInt32(block, blockOffset + headerOffset) != 0x00004550)
		                return null;

		            var pos = blockOffset + headerOffset + 6;

		            extracted_struct.NumberOfSections = BitConverter.ToInt16(block, pos); pos += 2;
		            extracted_struct.Sections = new List<MiniSection>();
		            //pos += 2;

		            extracted_struct.TimeStamp = BitConverter.ToUInt32(block, pos); pos += 4;
		            pos += 8;
		            extracted_struct.secOff = BitConverter.ToUInt16(block, pos); pos += 2;
		            pos += 2;
		            var magic = BitConverter.ToUInt16(block, pos); pos += 2;
		            extracted_struct.Is64 = magic == 0x20b;

		            if (extracted_struct.Is64)
		            {
		                pos += 14;
		                extracted_struct.EntryPoint = BitConverter.ToUInt32(block, pos); pos += 4;
		                extracted_struct.BaseOfCode = BitConverter.ToUInt32(block, pos); pos += 4;
		                // we wan't this to be page aligned to typical small page size
		                extracted_struct.ImageBaseOffset = pos & 0xfff;
		                extracted_struct.ImageBase = BitConverter.ToUInt64(block, pos); pos += 8;
		            } else {
		                pos += 18;
		                extracted_struct.EntryPoint = BitConverter.ToUInt32(block, pos); pos += 4;
		                extracted_struct.BaseOfCode = BitConverter.ToUInt32(block, pos); pos += 4;
		                extracted_struct.ImageBaseOffset = pos & 0xfff;
		                extracted_struct.ImageBase = BitConverter.ToUInt32(block, pos); pos += 4;
		            }
		            extracted_struct.SectionAlignment = BitConverter.ToUInt32(block, pos); pos += 4;
		            extracted_struct.FileAlignment = BitConverter.ToUInt32(block, pos); pos += 4;
		            pos += 16;
		            extracted_struct.SizeOfImage = BitConverter.ToUInt32(block, pos); pos += 4;
		            extracted_struct.SizeOfHeaders = BitConverter.ToUInt32(block, pos); pos += 4;
		            // checksum
		            pos += 4;
		            // subsys/characteristics
		            pos += 4;
		            // SizeOf/Stack/Heap/Reserve/Commit
		            if (extracted_struct.Is64)
		                pos += 32;
		            else
		                pos += 16;
		            // LoaderFlags
		            pos += 4;
		            // NumberOfRvaAndSizes
		            pos += 4;
		            // 16 DataDirectory entries, each is 8 bytes 4byte VA, 4byte Size
		            // we care about #6 since it's where we will find the GUID
		            pos += 6 * 8;
		            extracted_struct.DebugDirPos = BitConverter.ToUInt32(block, pos); pos += 4;
		            extracted_struct.DebugDirSize = BitConverter.ToUInt32(block, pos); pos += 4;
		            // move to IAT directory
		            pos += 5 * 8;
		            extracted_struct.ImportDirPos = BitConverter.ToUInt32(block, pos); pos += 4;
		            extracted_struct.ImportDirSize = BitConverter.ToUInt32(block, pos); pos += 4;
		            // move to "COM" directory (.net PE check)
		            pos += 8;
		            extracted_struct.ClrAddress = BitConverter.ToUInt32(block, pos); pos += 4;
		            extracted_struct.ClrSize = BitConverter.ToUInt32(block, pos); pos += 4;
		            if (extracted_struct.ClrAddress != 0)
		                extracted_struct.IsCLR = true;

		            var CurrEnd = extracted_struct.SizeOfHeaders;
		            /// implicit section for header
		            extracted_struct.Sections.Add(new MiniSection { VirtualSize = CurrEnd, RawFileSize = CurrEnd, RawFilePointer = 0, VirtualAddress = 0, Name = ".PEHeader", Characteristics = 0x20000000 });
		            // get to sections
		            pos = blockOffset + headerOffset + (extracted_struct.Is64 ? 0x108 : 0xF8);
		            for (int i = 0; i < extracted_struct.NumberOfSections; i++)
		            {
		                var rawStr = new String(
		                    new char[8] { (char) block[pos], (char) block[pos + 1], (char) block[pos + 2], (char) block[pos + 3],
		                    (char) block[pos + 4], (char) block[pos + 5], (char) block[pos + 6], (char) block[pos + 7] }); pos += 8;

		                var secStr = new string(rawStr.Where(c => char.IsLetterOrDigit(c) || char.IsPunctuation(c)).ToArray());

		                var Size = BitConverter.ToUInt32(block, pos); pos += 4;
		                var Pos = BitConverter.ToUInt32(block, pos); pos += 4;
		                var rawSize = BitConverter.ToUInt32(block, pos); pos += 4;
		                var rawPos = BitConverter.ToUInt32(block, pos); pos += 0x10;
		                var characteristic = BitConverter.ToUInt32(block, pos); pos += 4;

		                var currSecNfo = new MiniSection { VirtualSize = Size, VirtualAddress = Pos, RawFileSize = rawSize, RawFilePointer = rawPos, Name = secStr, Characteristics = characteristic };
		                extracted_struct.Sections.Add(currSecNfo);
		                if (secStr.StartsWith(@".reloc", StringComparison.Ordinal))
		                {
		                    extracted_struct.RelocSize = Size;
		                    extracted_struct.RelocPos = Pos;
		                }
		            }
		            return extracted_struct;
		        }
		    }


		    public class NativeMethods
		    {
		#if TEST
		        static void Main(string[] args)
		        {
		            Stopwatch sw = Stopwatch.StartNew();
		            long Hashed = 0, Shared = 0;
		            int lastId = 0;
		            foreach(var h in GetPageHashes(args))
		            {
		                //Console.WriteLine(h);
		                Hashed += h.HashedBlocks;
		                Shared += h.SharedAway;
		#if DEBUG
		                if (lastId != h.Id)
		                {
		                    Console.WriteLine($"{Hashed} hashed blocks, {Shared} shared.  {sw.Elapsed} ({(Hashed * 100.0) / sw.Elapsed.TotalSeconds:N3})");
		                    lastId = h.Id;
		                }
		#endif
		            }
		            Console.WriteLine($"Scanned = {ScanCnt}");
		        }
		#endif
		        static long ScanCnt = 0, TotShare = 0;
		        static long HIGHEST_USER_ADDRESS = 0x7ffffffeffff;
		        public static IEnumerable<MemPageHash> GetPageHashes()
		        {
		            long wsLen = 0;
		            IntPtr wsInfoLength = IntPtr.Zero;
		            IntPtr procHndl = IntPtr.Zero, workingSetPtr = IntPtr.Zero;
		            var sysinfo = new SYSTEM_INFO();
		            NativeMethods.GetSystemInfo(ref sysinfo);
		            var ha = SHA256.Create();
		            var name = new StringBuilder(1 << 16);

		            var SharedScannedPages = new List<long>();
		            var procs = GetProcessInfos(WTS_CURRENT_SERVER_HANDLE);
		            int readin = 0, Id = 0;

		            Dictionary<long, int> KnownPages = new Dictionary<long, int>();
		            var memBlock = new byte[4096];

		            var Regions = new List<MEMORY_BASIC_INFORMATION>();
		            var mem = new MEMORY_BASIC_INFORMATION();
		            var WSInfo = new List<PSAPI_WORKING_SET_EX_INFORMATION>();
		            PSAPI_WORKING_SET_EX_INFORMATION[] addRange = null;

		            foreach (var p in procs.Reverse()) {
		                try {
		                    try {
		                        bool DebuggerPresent = false;
		                        workingSetPtr = IntPtr.Zero;

		                        Id = p.pInfo.ProcessID;
		                        Console.WriteLine(String.Format("attempting to open PID {0}", Id));

		                        procHndl = NativeMethods.OpenProcess(ProcessAccessFlags.PROCESS_QUERY_INFORMATION | ProcessAccessFlags.PROCESS_VM_READ, true, (uint)Id);

		                        if (procHndl == NativeMethods.INVALID_HANDLE_VALUE || procHndl == IntPtr.Zero || Id == Process.GetCurrentProcess().Id)
		                            continue;

		                        CheckRemoteDebuggerPresent(procHndl, ref DebuggerPresent);
		                        if (DebuggerPresent)
		                            continue;

		                        var memInfo = (uint)p.pInfo.PeakWorkingSetSize;

		                        var wsInfoCnt = (memInfo / 0x100);
		                        wsLen = (0x10 * wsInfoCnt);

		                        wsInfoLength = new IntPtr(wsLen);
		                        workingSetPtr = Marshal.AllocHGlobal(wsInfoLength);
		                        var baseAddr = workingSetPtr.ToInt64();

		                        bool keepGoing = true;
		                        int wsCurr = 0;
		                        long AddressOffset = 0;
		                        long Address = 0;
		                        long NextAddress = Address + AddressOffset;

		                        do {
		                            var addrPtr = new IntPtr(NextAddress);
		                            NativeMethods.VirtualQueryEx(procHndl, addrPtr, ref mem, (int)sysinfo.dwPageSize);
		                            Regions.Add(mem);

		                            if (mem.State == StateEnum.MEM_COMMIT)
		                            {
		                                for (long startAddr = mem.BaseAddress; startAddr < (mem.BaseAddress + mem.RegionSize); startAddr += sysinfo.dwPageSize)
		                                {
		                                    if (wsCurr < wsInfoCnt)
		                                    {
		                                        Marshal.WriteInt64(workingSetPtr, wsCurr * 0x10, startAddr);
		                                        wsCurr++;
		                                    }
		                                    else
		                                    {
		                                        keepGoing = false;
		                                        break;
		                                    }
		                                }
		                            }
		                            AddressOffset += mem.RegionSize;
		                            NextAddress = Address + AddressOffset;

		                            if ((mem.RegionSize == 0) || (NextAddress >= HIGHEST_USER_ADDRESS) || (NextAddress < 0))
		                                keepGoing = false;

		                        } while (keepGoing);

		                        NativeMethods.QueryWorkingSetEx(procHndl, workingSetPtr, wsInfoLength.ToInt32());
		                        addRange = GenerateWorkingSetExArray(workingSetPtr, wsCurr);
		                        WSInfo.AddRange(addRange);
		                    }
		                    catch (Exception ex) { Console.WriteLine(String.Format("Exception in processing: {0} {1}", wsInfoLength, ex));
		                    } finally { Marshal.FreeHGlobal(workingSetPtr); }

		                    foreach (var region in Regions)
		                    {
		                        var rHash = new MemPageHash();
		                        Extract e = null;
		                        if (((int)region.AllocationProtect & 0xf0) != 0)
		                        {
		                            GetModuleFileNameEx(procHndl, new IntPtr(region.AllocationBase), name, 1 << 16);

		                            // try to load it from memory
		                            try {
		                                // see if we have a header
		                                NativeMethods.ReadProcessMemory(procHndl, new IntPtr(region.AllocationBase), memBlock, memBlock.Length, readin);
		                            } catch (Exception ex) { Console.Write(ex); }
		                                
		                            e = Extract.IsBlockaPE(memBlock);
		                            if(e != null)
		                                e.FileName = name.ToString();

		                            Byte[] hdrHash = null;

		                            if (memBlock != null)
		                                hdrHash = ha.ComputeHash(memBlock);

		                            rHash.ModuleName = name.ToString();
		                            rHash.Id = p.pInfo.ProcessID;
		                            rHash.ProcessName = p.pInfo.ProcessName;
		                            rHash.AllocationBase = region.AllocationBase;
		                            rHash.BaseAddress = region.BaseAddress;
		                            rHash.Size = region.RegionSize;
		                            rHash.HdrHash = Convert.ToBase64String(hdrHash);
		                            if(e != null) {
		                                rHash.TimeDateStamp = e.TimeStamp;
		                                rHash.ImageSize = (uint) e.SizeOfImage;
		                            }

		                            // if we have "new" executable pages scan them
		                            foreach (var addr in from range in addRange
		                                                    where
		                                        (range.VirtualAddress >= region.BaseAddress &&
		                                        range.VirtualAddress < (region.BaseAddress + region.RegionSize)) &&
		                                        ((range.WorkingSetInfo.Block1.Protection & 0xf0) != 0)
		                                                select range)
		                            {
		                                if (!KnownPages.ContainsKey(addr.VirtualAddress))
		                                {
		                                    if (addr.WorkingSetInfo.Block1.ShareCnt != 0)
		                                        KnownPages.Add(addr.VirtualAddress, Id);

		                                    ScanCnt++;
		                                    if (!NativeMethods.ReadProcessMemory(procHndl, new IntPtr(addr.VirtualAddress), memBlock, memBlock.Length, readin))
		                                        rHash.HashSet.Add(new PageHashBlock() { Address = addr.VirtualAddress, Hash = "***BAD_READ***" } );
		                                    else
		                                    {
		                                        rHash.HashedBlocks++;
		                                        rHash.HashSet.Add(new PageHashBlock() { Address = addr.VirtualAddress, Hash = Convert.ToBase64String(ha.ComputeHash(memBlock)) } );
		                                    }
		                                }
		                                else
		                                {
		                                    TotShare++;
		                                    rHash.SharedAway++;
		                                }
		                            }
		                            if(rHash.HashSet.Count > 0)
		                                yield return rHash;
		                        }
		                    }
		                }
		                finally { CloseHandle(procHndl); }
		            }
		            Console.WriteLine(String.Format("Scan count is {0} - Saved scan/shared pages {1}", ScanCnt, TotShare));
		            yield break;
		        }
		        // Generates an array containing working set information based on a pointer in memory.
		        private static PSAPI_WORKING_SET_EX_INFORMATION[] GenerateWorkingSetExArray(IntPtr workingSetPointer, int entries)
		        {
		            var workingSet = new PSAPI_WORKING_SET_EX_INFORMATION[entries];

		            for (var i = 0; i < entries; i++)
		            {
		                var VA = Marshal.ReadInt64(workingSetPointer, (i * 0x10));
		                var flags = Marshal.ReadInt64(workingSetPointer, (i * 0x10) + 8);

		                workingSet[i].VirtualAddress = VA;
		                workingSet[i].WorkingSetInfo.Flags = flags;
		            }

		            return workingSet;
		        }
		        private static IntPtr WTS_CURRENT_SERVER_HANDLE = (IntPtr)null;

		        public class SessionInfo
		        {
		            public WTS_PROCESS_INFO_EX pInfo;
		            public string User;
		            public SID_NAME_USE Use;
		        }

		        private static SessionInfo[] GetProcessInfos(IntPtr ServerHandle)
		        {
		            IntPtr pSaveMem = IntPtr.Zero;
		            SessionInfo[] rv = null;
		            try
		            {
		                IntPtr pProcessInfo = IntPtr.Zero;
		                int processCount = 0;
		                IntPtr useProcessesExStructure = new IntPtr(1);

		                if (WTSEnumerateProcessesExW(ServerHandle, ref useProcessesExStructure, WTS_ANY_SESSION, ref pSaveMem, ref processCount))
		                {
		                    pProcessInfo = new IntPtr(pSaveMem.ToInt64());
		                    const int NO_ERROR = 0;
		                    const int ERROR_INSUFFICIENT_BUFFER = 122;

		                    rv = new SessionInfo[processCount];

		                    for (int i = 0; i < processCount; i++)
		                    {
		                        rv[i] = new SessionInfo() { pInfo = (WTS_PROCESS_INFO_EX)Marshal.PtrToStructure(pProcessInfo, typeof(WTS_PROCESS_INFO_EX)) };

		                        if (rv[i].pInfo.UserSid != IntPtr.Zero)
		                        {
		                            byte[] Sid = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		                            Marshal.Copy(rv[i].pInfo.UserSid, Sid, 0, 14);
		                            StringBuilder name = new StringBuilder();

		                            uint cchName = (uint)name.Capacity;
		                            SID_NAME_USE sidUse;
		                            StringBuilder referencedDomainName = new StringBuilder();

		                            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;

		                            if (LookupAccountSid(null, Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
		                            {
		                                int err = Marshal.GetLastWin32Error();

		                                if (err == ERROR_INSUFFICIENT_BUFFER)
		                                {
		                                    name.EnsureCapacity((int)cchName);
		                                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);

		                                    err = NO_ERROR;

		                                    if (!LookupAccountSid(null, Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
		                                        err = Marshal.GetLastWin32Error();
		                                }
		                                rv[i].Use = sidUse;
		                                rv[i].User = name.ToString();
		                            }
		                        }
		                        pProcessInfo = IntPtr.Add(pProcessInfo, Marshal.SizeOf(typeof(WTS_PROCESS_INFO_EX)));
		                    }
		                }
		            }
		            catch (Exception ex) { Console.WriteLine(ex.Message + "\r\n" + Marshal.GetLastWin32Error()); }
		            finally
		            {
		                if (pSaveMem != IntPtr.Zero)
		                    WTSFreeMemory(pSaveMem);
		            }
		            return rv;
		        }

		        [DllImport("psapi.dll")]
		        private static extern uint GetModuleFileNameEx(IntPtr hWnd, IntPtr hModule, StringBuilder lpFileName, int nSize);

		        [DllImport("wtsapi32.dll", SetLastError = true)]
		        private static extern bool WTSEnumerateProcessesExW(
		            IntPtr hServer, // A handle to an RD Session Host server.. 
		            ref IntPtr pLevel, // must be 1 - To return an array of WTS_PROCESS_INFO_EX structures, specify one.
		            Int32 SessionID, // The session for which to enumerate processes. To enumerate processes for all sessions on the server, specify WTS_ANY_SESSION.
		            ref IntPtr ppProcessInfo, // A pointer to a variable that receives a pointer to an array of WTS_PROCESS_INFO or WTS_PROCESS_INFO_EX structures. The type of structure is determined by the value passed to the pLevel parameter. Each structure in the array contains information about an active process. When you have finished using the array, free it by calling the WTSFreeMemoryEx function. You should also set the pointer to NULL.
		            ref Int32 pCount); // pointer to number of processes -> A pointer to a variable that receives the number of structures returned in the buffer referenced by the ppProcessInfo parameter.

		        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		        private static extern bool LookupAccountSid(
		            string lpSystemName,
		            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
		            StringBuilder lpName,
		            ref uint cchName,
		            StringBuilder ReferencedDomainName,
		            ref uint cchReferencedDomainName,
		            out SID_NAME_USE peUse);

		        [DllImport("wtsapi32.dll", ExactSpelling = true, SetLastError = false)]
		        public static extern void WTSFreeMemory(IntPtr memory);

		        [DllImport("kernel32.dll")]
		        public static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO lpSystemInfo);

		        [DllImport("psapi.dll", SetLastError = true)]
		        public static extern int QueryWorkingSetEx(IntPtr hProcess, IntPtr info, int size);

		        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

		        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

		        [DllImport("kernel32.dll")]
		        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
		        [DllImport("kernel32.dll")]
		        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
		        [DllImport("kernel32.dll")]
		        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, [Out] int lpNumberOfBytesRead);
		        [DllImport("kernel32.dll")]
		        public static extern bool CloseHandle(IntPtr hObject);

		        [StructLayout(LayoutKind.Sequential)]
		        public struct SYSTEM_INFO
		        {
		            public _PROCESSOR_INFO_UNION uProcessorInfo;
		            public uint dwPageSize;
		            public IntPtr lpMinimumApplicationAddress;
		            public IntPtr lpMaximumApplicationAddress;
		            public IntPtr dwActiveProcessorMask;
		            public uint dwNumberOfProcessors;
		            public uint dwProcessorType;
		            public uint dwAllocationGranularity;
		            public ushort dwProcessorLevel;
		            public ushort dwProcessorRevision;
		        }

		        [StructLayout(LayoutKind.Explicit)]
		        public struct _PROCESSOR_INFO_UNION
		        {
		            [FieldOffset(0)]
		            public uint dwOemId;
		            [FieldOffset(0)]
		            public ushort wProcessorArchitecture;
		            [FieldOffset(2)]
		            public ushort wReserved;
		        }

		        // Struct to hold performace memory counters.
		        [StructLayout(LayoutKind.Sequential)]
		        public struct PROCESS_MEMORY_COUNTERS_EX
		        {
		            public int cb;
		            public int PageFaultCount;
		            public int PeakWorkingSetSize;
		            public int WorkingSetSize;
		            public int QuotaPeakPagedPoolUsage;
		            public int QuotaPagedPoolUsage;
		            public int QuotaPeakNonPagedPoolUsage;
		            public int QuotaNonPagedPoolUsage;
		            public int PagefileUsage;
		            public int PeakPagefileUsage;
		            public int publicUsage;
		        }

		        [StructLayout(LayoutKind.Sequential)]
		        public class PSAPI_WORKING_SET_INFORMATION
		        {
		            public int NumberOfEntries;

		            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.Struct)]
		            public PSAPI_WORKING_SET_BLOCK[] WorkingSetInfo;
		        }

		        [StructLayout(LayoutKind.Sequential)]
		        public struct BLOCK
		        {
		            public uint bitvector1;

		            public uint Protection;
		            public uint ShareCount;
		            public uint Reserved;
		            public uint VirtualPage;

		            public uint Shared
		            {
		                get { return (((this.bitvector1 & 256u) >> 8)); }
		            }
		        }

		        [StructLayout(LayoutKind.Explicit)]
		        public struct PSAPI_WORKING_SET_BLOCK
		        {
		            [FieldOffset(0)]
		            public uint Flags;

		            [FieldOffset(0)]
		            public BLOCK Block1;
		        }

		        [StructLayout(LayoutKind.Sequential, Size = 8)]
		        public struct BLOCK_EX
		        {
		            public long Bits;
		            const int Valid = 1;
		            const int ShareCount = 3; // # up to 7 of shared usage
		            const int Win32Protection = 11;
		            const int Shareable = 1;
		            const int Node = 6;
		            const int Locked = 1;
		            const int LargePage = 1;
		            const int Reserved = 7;
		            const int Bad = 1;
		            const int ReservedUlong = 32;
		            static BLOCK_EX_INVALID Invalid;
		            public bool IsValid { get { return (Bits & 1) != 0; } }
		            public int ShareCnt { get { return (int)(Bits >>  Valid) & 0x7; } }
		            public int Protection { get { return (int) (Bits >> ShareCount + Valid) & 0x7FF; } }
		            public bool IsShareable { get { return (Bits >> (Win32Protection + ShareCount + Valid) & 1) != 0; } }
		            public int NodeId { get { return (int)(Bits >> Shareable + Win32Protection + ShareCount + Valid) & 0x3f; } }
		            public bool IsLocked { get { return (Bits >> (Node + Shareable + Win32Protection + ShareCount + Valid) & 1) != 0; } }
		            public bool IsLargePage { get { return Bits >> (Locked + Node + Shareable + Win32Protection + ShareCount + Valid) != 0; } }
		            public int ReservedBits { get { return (int) Bits >> (LargePage + Locked + Node + Shareable + Win32Protection + ShareCount + Valid); } }
		            public bool IsBad { get { return Bits >> (Reserved + LargePage + Locked + Node + Shareable + Win32Protection + ShareCount + Valid) != 0; } }
		            public int ReservedUlongBits { get { return (int)(Bits >> 32); } }
		        }
		        [StructLayout(LayoutKind.Sequential)]
		        public struct BLOCK_EX_INVALID
		        {
		            public long Bits;
		            const int Valid = 1;
		            const int Reserved0 = 14;
		            const int Shared = 1;
		            const int Reserved1 = 15;
		            const int Bad = 1;
		            const int ReservedUlong = 32;
		            public bool IsValid { get { return (Bits & 1) != 0; } }
		            public int ReservedBits0 { get { return (int) (Bits >> 1) & 0x3FFF; } }
		            public bool IsShared { get { return ((Bits >> 15) & 1) != 0; } }
		            public int ReservedBits1 { get { return (int)(Bits >> 16) & 0x7FFF; } }
		            public bool IsBad { get { return ((Bits >> 31) & 1) != 0; } }
		            public int ReservedUlongBits { get { return (int)(Bits >> 32); } }
		        }
		        [StructLayout(LayoutKind.Explicit, Size = 8)]
		        public struct PSAPI_WORKING_SET_EX_BLOCK
		        {
		            [FieldOffset(0)]
		            public long Flags;

		            [FieldOffset(0)]
		            public BLOCK_EX Block1;

		            public override string ToString() { 
		            return String.Format("{0:X} IsValid:{1} CanShare:{2} ShareCnt:{3:x} IsLocked:{4} IsLarge:{5} IsBad:{6} Protection:{7:X} Node:{8:x} Reserved:{9:x} ReservedLong:{10:x}",
		            Block1.Bits, Block1.IsValid, Block1.IsShareable, Block1.ShareCnt, Block1.IsLocked, Block1.IsLargePage, Block1.IsBad, Block1.Protection, Block1.NodeId, Block1.ReservedBits, Block1.ReservedUlongBits);
		            }
		        }

		        [StructLayout(LayoutKind.Sequential, Size = 0x10)]
		        public struct PSAPI_WORKING_SET_EX_INFORMATION
		        {
		            public long VirtualAddress;
		            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.Struct)]
		            public PSAPI_WORKING_SET_EX_BLOCK WorkingSetInfo;
		            public override string ToString() 
		            { return String.Format("VA = {0:X16} - {1}", VirtualAddress, WorkingSetInfo); } 
		        }

		        private const Int32 WTS_ANY_SESSION = -2;
		        [Flags]
		        public enum ProcessAccessFlags : uint
		        {
		            PROCESS_VM_READ = 0x00000010,
		            PROCESS_QUERY_INFORMATION = 0x00000400,
		            ALL = 0x001F0FFF
		        }

		        [Flags]
		        public enum AllocationProtectEnum : uint
		        {
		            PAGE_EXECUTE = 0x00000010,
		            PAGE_EXECUTE_READ = 0x00000020,
		            PAGE_EXECUTE_READWRITE = 0x00000040,
		            PAGE_EXECUTE_WRITECOPY = 0x00000080,
		            PAGE_NOACCESS = 0x00000001,
		            PAGE_READONLY = 0x00000002,
		            PAGE_READWRITE = 0x00000004,
		            PAGE_WRITECOPY = 0x00000008,
		            PAGE_GUARD = 0x00000100,
		            PAGE_NOCACHE = 0x00000200,
		            PAGE_WRITECOMBINE = 0x00000400,
		        }

		        [Flags]
		        public enum StateEnum : uint
		        {
		            MEM_COMMIT = 0x00001000,
		            MEM_FREE = 0x00010000,
		            MEM_RESERVE = 0x00002000,
		        }

		        [Flags]
		        public enum TypeEnum : uint
		        {
		            MEM_IMAGE = 0x01000000,
		            MEM_MAPPED = 0x00040000,
		            MEM_PRIVATE = 0x00020000,
		        }

		        [StructLayout(LayoutKind.Sequential)]
		        public struct MEMORY_BASIC_INFORMATION
		        {
		            public long BaseAddress;
		            public long AllocationBase;
		            public AllocationProtectEnum AllocationProtect;
		            public long RegionSize;
		            public StateEnum State;
		            public AllocationProtectEnum Protect;
		            public TypeEnum Type;
		        }

		        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		        [System.Runtime.InteropServices.BestFitMapping(true)]
		        public struct WTS_PROCESS_INFO_EX
		        {
		            public Int32 SessionID;			// The Remote Desktop Services session identifier for the session associated with the process.
		            public Int32 ProcessID;			// The process identifier that uniquely identifies the process on the RD Session Host server.
		            [MarshalAs(UnmanagedType.LPWStr)]
		            public string ProcessName;		// A pointer to a null-terminated string that contains the name of the executable file associated with the process.
		            public IntPtr UserSid;			// A pointer to the user security identifiers (SIDs) in the primary access token of the process. 
		            public Int32 NumberOfThreads;	// The number of threads in the process.
		            public Int32 HandleCount;		// The number of handles in the process.
		            public Int32 PagefileUsage;		// The page file usage of the process, in bytes.
		            public Int32 PeakPagefileUsage;	// The peak page file usage of the process, in bytes.
		            public Int32 WorkingSetSize;	// The working set size of the process, in bytes.
		            public Int32 PeakWorkingSetSize;// The peak working set size of the process, in bytes.
		            public long UserTime;	// The amount of time, in milliseconds, the process has been running in user mode.
		            public long KernelTime;// The amount of time, in milliseconds, the process has been running in kernel mode.
		        }

		        public  enum SID_NAME_USE
		        {
		            User = 1,
		            Group,
		            Domain,
		            Alias,
		            WellKnownGroup,
		            DeletedAccount,
		            Invalid,
		            Unknown,
		            Computer
		        }
		    }
		}
"@
		# I haven't found a good way to marshal the PS Object's back nativly so I need to use JSON from the remote side
		# Since I got back this wonky Unserialized.xy type...
		# I guess I could custom marshal it into string/XML blah
		#Install-Package $jsonLibName
		$jsonLibName = "newtonsoft.json"
		$jsonLib = @(Get-ChildItem -Filter "newtonsoft.json.dll" -Recurse "C:\Program Files\WindowsPowerShell\Modules")[0]
		[void][Reflection.Assembly]::LoadFile($jsonLib.FullName)
		
		$codeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider
		$location = [PsObject].Assembly.Location
		$compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
		$assemblyRange = @("System.dll", $location)
		$compileParams.ReferencedAssemblies.AddRange($assemblyRange)
		$compileParams.GenerateInMemory = $True
		[void]$codeProvider.CompileAssemblyFromSource($compileParams, $code)
		
		Add-Type -TypeDefinition $code -Language CSharp
		
		foreach ($h in [MemTest.NativeMethods]::GetPageHashes())
		{
			[Newtonsoft.Json.JsonConvert]::SerializeObject([MemTest.MemPageHash]$h, [Newtonsoft.Json.Formatting]::Indented)
		}
	}
}
		
$code2 =
@"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

namespace MemTest
{
public class MemPageHash
{
    public string HdrHash;
    public uint TimeDateStamp;
    public long AllocationBase;
    public long BaseAddress;
    public long Size;
    public uint ImageSize;
    public int Id;
    public string ProcessName;
    public string ModuleName;
    public int SharedAway;
    public int HashedBlocks;
    public HashSet<PageHashBlock> HashSet = new HashSet<PageHashBlock>();

    public override string ToString() { 
    return String.Format("{0} {1} {2} VA:{3:x} PageHasheCount:{4} SharedAway:{5}",
     ProcessName, Path.GetFileName(ModuleName), Id, BaseAddress, HashSet.Count, SharedAway); }
}

public class PageHashBlock
{
    public long Address;
    public string Hash;
}

public class PageHashBlockResult
{
    public long Address;
    public bool HashCheckEquivalant;
}
}
"@
#Install-Package $jsonLibName

$jsonLibName = "newtonsoft.json"
$jsonLib = @(Get-ChildItem -Filter "newtonsoft.json.dll" -Recurse "C:\Program Files\WindowsPowerShell\Modules")[0]
[void][Reflection.Assembly]::LoadFile($jsonLib.FullName)
$codeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider

$location = [PsObject].Assembly.Location
$compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
$assemblyRange = @("System.dll", $location)
$compileParams.ReferencedAssemblies.AddRange($assemblyRange)
$compileParams.GenerateInMemory = $True
[void]$codeProvider.CompileAssemblyFromSource($compileParams, $code2)
Add-Type -TypeDefinition $code2 -Language CSharp

#Import-Module –Name PoshRSJob

$uri = "https://pdb2json.azurewebsites.net/api/PageHash/x"
$propertiesType = ("System.Collections.Generic.HashSet" + '`' + "1") -as "Type"
$propertiesType = $propertiesType.MakeGenericType("MemTest.PageHashBlockResult" -as "Type")
$properties = [Activator]::CreateInstance($propertiesType)
$type = [System.Collections.Generic.HashSet[MemTest.PageHashBlockResult]]

# I gues these would be good to get from the command line
$serverName = [Environment]::GetEnvironmentVariable("REMOTE_HOST")
$username = [Environment]::GetEnvironmentVariable("USER_NAME")
$password = [Environment]::GetEnvironmentVariable("PASS_WORD")
$adjPwd = $password | ConvertTo-SecureString -asPlainText -Force
$testCred = (New-Object System.Management.Automation.PSCredential($username, $adjPwd))

$ArrayList = New-Object -TypeName 'System.Collections.ArrayList';
$s = New-PSSession -ComputerName Server16 -Credential $testCred
$job = Invoke-Command -Session $s -ScriptBlock $block -AsJob
$output = Receive-Job -Job $job

foreach ($o in $output)
{
	#send web request for hash validation
	$content = Invoke-WebRequest -Uri $uri -Method POST -Body $o -ContentType "application/json" -UseBasicParsing | Select-Object Content
	
	#decode back to PS 
	$rv = [Newtonsoft.Json.JsonConvert]::DeserializeObject($content.Content, $type)
	
	$hashAction = [pscustomobject]@{
		Test	   = $o
		Result	   = $rv
	}
	[void]$ArrayList.Add($hashAction)
	if (($ArrayList.Count % 100) -eq 0)
	{
		Write-Host "Result count: " + $ArrayList.Count
	}
}

Write-Host "Done. Collected " + $ArrayList.Count + " results."


