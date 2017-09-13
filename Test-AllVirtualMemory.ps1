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
	
	.DESCRIPTION
		A detailed description of the remote-hash-memory.ps1 file.
	
	.PARAMETER TargetHost
		A description of the TargetHost parameter.
	
	.PARAMETER aUserName
		A description of the aUserName parameter.
	
	.PARAMETER aPassWord
		A description of the aPassWord parameter.
	
	.PARAMETER ProcNameGlob
		A description of the ProcNameGlob parameter.
	.PARAMETER MaxThreads
		How Parallel to go (default 256 :)
	.PARAMETER GUIObject
        Show a UI of the results
    .PARAMETER ElevatePastAdmin
		Use PowerSploit/Get-System to elevate to a system token
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
	
	.NOTES
		Additional information about the file.
#>
param
(
	[String]$TargetHost = "",
	[String]$aUserName = $env:UserName,
	[String]$aPassWord = "",
	[String[]]$ProcNameGlob = $null,
	[int]$MaxThreads = 256,
    [Switch]$GUIOutput,
    [Switch]$ElevatePastAdmin
)
# if envronment is set use it, otherwise cmd line
$serverName = [Environment]::GetEnvironmentVariable("REMOTE_HOST")
if ([System.String]::IsNullOrWhiteSpace($serverName))
{
	$serverName = $TargetHost
}
$username = [Environment]::GetEnvironmentVariable("USER_NAME")
if ([System.String]::IsNullOrWhiteSpace($username))
{
	$username = $aUserName
}
$password = [Environment]::GetEnvironmentVariable("PASS_WORD")
if ([string]::IsNullOrWhiteSpace($password)) {
	$password = $aPassWord | ConvertTo-SecureString -AsPlainText -Force
}

$testCred = (New-Object System.Management.Automation.PSCredential($username, $password ))

Function Remove-InvalidFileNameChars {
    param(
      [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
      [String]$Name
    )
  
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re)
  }

function blockfun ($ProcNameGlob) {
        # Embed Get-System in here from PowerSploit makes life easier, I also modified it a bit to make life easier ;)
        function Get-System {
        param(
            [String]
            $Technique = 'Token',

            [Switch]
            $WhoAmI
        )
        # written by @mattifestation and adapted from https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot
        Function Local:Get-SystemToken {
            [CmdletBinding()] param()

            $DynAssembly = New-Object Reflection.AssemblyName('AdjPriv')
            $AssemblyBuilder = [Appdomain]::Currentdomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('AdjPriv', $False)
            $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'

            $TokPriv1LuidTypeBuilder = $ModuleBuilder.DefineType('TokPriv1Luid', $Attributes, [System.ValueType])
            $TokPriv1LuidTypeBuilder.DefineField('Count', [Int32], 'Public') | Out-Null
            $TokPriv1LuidTypeBuilder.DefineField('Luid', [Int64], 'Public') | Out-Null
            $TokPriv1LuidTypeBuilder.DefineField('Attr', [Int32], 'Public') | Out-Null
            $TokPriv1LuidStruct = $TokPriv1LuidTypeBuilder.CreateType()

            $LuidTypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType])
            $LuidTypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
            $LuidTypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
            $LuidStruct = $LuidTypeBuilder.CreateType()

            $Luid_and_AttributesTypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType])
            $Luid_and_AttributesTypeBuilder.DefineField('Luid', $LuidStruct, 'Public') | Out-Null
            $Luid_and_AttributesTypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
            $Luid_and_AttributesStruct = $Luid_and_AttributesTypeBuilder.CreateType()

            $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
            $ConstructorValue = [Runtime.InteropServices.UnmanagedType]::ByValArray
            $FieldArray = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

            $TokenPrivilegesTypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType])
            $TokenPrivilegesTypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
            $PrivilegesField = $TokenPrivilegesTypeBuilder.DefineField('Privileges', $Luid_and_AttributesStruct.MakeArrayType(), 'Public')
            $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 1))
            $PrivilegesField.SetCustomAttribute($AttribBuilder)
            $TokenPrivilegesStruct = $TokenPrivilegesTypeBuilder.CreateType()

            $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder(
                ([Runtime.InteropServices.DllImportAttribute].GetConstructors()[0]),
                'advapi32.dll',
                @([Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')),
                @([Bool] $True)
            )

            $AttribBuilder2 = New-Object Reflection.Emit.CustomAttributeBuilder(
                ([Runtime.InteropServices.DllImportAttribute].GetConstructors()[0]),
                'kernel32.dll',
                @([Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')),
                @([Bool] $True)
            )

            $Win32TypeBuilder = $ModuleBuilder.DefineType('Win32Methods', $Attributes, [ValueType])
            $Win32TypeBuilder.DefinePInvokeMethod(
                'OpenProcess',
                'kernel32.dll',
                [Reflection.MethodAttributes] 'Public, Static',
                [Reflection.CallingConventions]::Standard,
                [IntPtr],
                @([UInt32], [Bool], [UInt32]),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                'Auto').SetCustomAttribute($AttribBuilder2)

            $Win32TypeBuilder.DefinePInvokeMethod(
                'CloseHandle',
                'kernel32.dll',
                [Reflection.MethodAttributes] 'Public, Static',
                [Reflection.CallingConventions]::Standard,
                [Bool],
                @([IntPtr]),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                'Auto').SetCustomAttribute($AttribBuilder2)

            $Win32TypeBuilder.DefinePInvokeMethod(
                'DuplicateToken',
                'advapi32.dll',
                [Reflection.MethodAttributes] 'Public, Static',
                [Reflection.CallingConventions]::Standard,
                [Bool],
                @([IntPtr], [Int32], [IntPtr].MakeByRefType()),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                'Auto').SetCustomAttribute($AttribBuilder)

            $Win32TypeBuilder.DefinePInvokeMethod(
                'SetThreadToken',
                'advapi32.dll',
                [Reflection.MethodAttributes] 'Public, Static',
                [Reflection.CallingConventions]::Standard,
                [Bool],
                @([IntPtr], [IntPtr]),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                'Auto').SetCustomAttribute($AttribBuilder)

            $Win32TypeBuilder.DefinePInvokeMethod(
                'OpenProcessToken',
                'advapi32.dll',
                [Reflection.MethodAttributes] 'Public, Static',
                [Reflection.CallingConventions]::Standard,
                [Bool],
                @([IntPtr], [UInt32], [IntPtr].MakeByRefType()),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                'Auto').SetCustomAttribute($AttribBuilder)

            $Win32TypeBuilder.DefinePInvokeMethod(
                'LookupPrivilegeValue',
                'advapi32.dll',
                [Reflection.MethodAttributes] 'Public, Static',
                [Reflection.CallingConventions]::Standard,
                [Bool],
                @([String], [String], [IntPtr].MakeByRefType()),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                'Auto').SetCustomAttribute($AttribBuilder)

            $Win32TypeBuilder.DefinePInvokeMethod(
                'AdjustTokenPrivileges',
                'advapi32.dll',
                [Reflection.MethodAttributes] 'Public, Static',
                [Reflection.CallingConventions]::Standard,
                [Bool],
                @([IntPtr], [Bool], $TokPriv1LuidStruct.MakeByRefType(),[Int32], [IntPtr], [IntPtr]),
                [Runtime.InteropServices.CallingConvention]::Winapi,
                'Auto').SetCustomAttribute($AttribBuilder)
            
            $Win32Methods = $Win32TypeBuilder.CreateType()

            $Win32Native = [Int32].Assembly.GetTypes() | ? {$_.Name -eq 'Win32Native'}
            $GetCurrentProcess = $Win32Native.GetMethod(
                'GetCurrentProcess',
                [Reflection.BindingFlags] 'NonPublic, Static'
            )
                
            $SE_PRIVILEGE_ENABLED = 0x00000002
            $STANDARD_RIGHTS_REQUIRED = 0x000F0000
            $STANDARD_RIGHTS_READ = 0x00020000
            $TOKEN_ASSIGN_PRIMARY = 0x00000001
            $TOKEN_DUPLICATE = 0x00000002
            $TOKEN_IMPERSONATE = 0x00000004
            $TOKEN_QUERY = 0x00000008
            $TOKEN_QUERY_SOURCE = 0x00000010
            $TOKEN_ADJUST_PRIVILEGES = 0x00000020
            $TOKEN_ADJUST_GROUPS = 0x00000040
            $TOKEN_ADJUST_DEFAULT = 0x00000080
            $TOKEN_ADJUST_SESSIONID = 0x00000100
            $TOKEN_READ = $STANDARD_RIGHTS_READ -bor $TOKEN_QUERY
            $TOKEN_ALL_ACCESS = $STANDARD_RIGHTS_REQUIRED -bor
                $TOKEN_ASSIGN_PRIMARY -bor
                $TOKEN_DUPLICATE -bor
                $TOKEN_IMPERSONATE -bor
                $TOKEN_QUERY -bor
                $TOKEN_QUERY_SOURCE -bor
                $TOKEN_ADJUST_PRIVILEGES -bor
                $TOKEN_ADJUST_GROUPS -bor
                $TOKEN_ADJUST_DEFAULT -bor
                $TOKEN_ADJUST_SESSIONID

            [long]$Luid = 0

            $tokPriv1Luid = [Activator]::CreateInstance($TokPriv1LuidStruct)
            $tokPriv1Luid.Count = 1
            $tokPriv1Luid.Luid = $Luid
            $tokPriv1Luid.Attr = $SE_PRIVILEGE_ENABLED

            $RetVal = $Win32Methods::LookupPrivilegeValue($Null, "SeDebugPrivilege", [ref]$tokPriv1Luid.Luid)

            $htoken = [IntPtr]::Zero
            $RetVal = $Win32Methods::OpenProcessToken($GetCurrentProcess.Invoke($Null, @()), $TOKEN_ALL_ACCESS, [ref]$htoken)

            $tokenPrivileges = [Activator]::CreateInstance($TokenPrivilegesStruct)
            $RetVal = $Win32Methods::AdjustTokenPrivileges($htoken, $False, [ref]$tokPriv1Luid, 12, [IntPtr]::Zero, [IntPtr]::Zero)

            if(-not($RetVal)) {
                Write-Error "AdjustTokenPrivileges failed, RetVal : $RetVal" -ErrorAction Stop
            }
            
            $LocalSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value

            $SystemHandle = Get-WmiObject -Class Win32_Process | ForEach-Object {
                try {
                    $OwnerInfo = $_.GetOwner()
                    if ($OwnerInfo.Domain -and $OwnerInfo.User) {
                        $OwnerString = "$($OwnerInfo.Domain)\$($OwnerInfo.User)".ToUpper()

                        if ($OwnerString -eq $LocalSystemNTAccount.ToUpper()) {
                            $Process = Get-Process -Id $_.ProcessId

                            $Handle = $Win32Methods::OpenProcess(0x0400, $False, $Process.Id)
                            if ($Handle) {
                                $Handle
                            }
                        }
                    }
                }
                catch {}
            } | Where-Object {$_ -and ($_ -ne 0)} | Select -First 1
            
            if ((-not $SystemHandle) -or ($SystemHandle -eq 0)) {
                Write-Error 'Unable to obtain a handle to a system process.'
            } 
            else {
                [IntPtr]$SystemToken = [IntPtr]::Zero
                $RetVal = $Win32Methods::OpenProcessToken(([IntPtr][Int] $SystemHandle), ($TOKEN_IMPERSONATE -bor $TOKEN_DUPLICATE), [ref]$SystemToken);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                Write-Verbose "OpenProcessToken result: $RetVal"
                Write-Verbose "OpenProcessToken result: $LastError"

                [IntPtr]$DulicateTokenHandle = [IntPtr]::Zero
                $RetVal = $Win32Methods::DuplicateToken($SystemToken, 2, [ref]$DulicateTokenHandle);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

                Write-Verbose "DuplicateToken result: $LastError"

                $RetVal = $Win32Methods::SetThreadToken([IntPtr]::Zero, $DulicateTokenHandle);$LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if(-not($RetVal)) {
                    Write-Error "SetThreadToken failed, RetVal : $RetVal" -ErrorAction Stop
                }
                Write-Verbose "SetThreadToken result: $LastError"
                $null = $Win32Methods::CloseHandle($Handle)
            }
        }
        if($PSBoundParameters['WhoAmI']) {
            Write-Output "$([Environment]::UserDomainName)\$([Environment]::UserName)"
            return
        }
        else {
            if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
                Write-Error "Script must be run as administrator" -ErrorAction Stop
            }
            Get-SystemToken
            Write-Output "Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
        }
    }
	try
	{
		$nm = New-Object MemTest+NativeMethods
	}
	catch
	{
$Code = @"
// Copyright Shane Macaulay / K2 (smacaulay@gmail.com) / (github.com/K2) AGPL 3.0
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
namespace MemTest
{
#region PowerShell Exported Types
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
#endregion
public static class NativeMethods
{
    private static long ScanCnt = 0, TotShare = 0;
    static long HIGHEST_USER_ADDRESS = 0;
    public static Dictionary<int, Dictionary<long, MemState>> AllMemState = new Dictionary<int, Dictionary<long, MemState>>();
    public class MemState
    {
        public long Address;
        public Extract e;
        public MemPageHash pHash;
    }
    static void Main(string[] args)
    {
#if DEBUG
        var listeners = new TraceListener[] { new TextWriterTraceListener(Console.Out) };
        Debug.Listeners.AddRange(listeners);
#else

#endif
        long Hashed = 0, Shared = 0;
        try { Process.EnterDebugMode(); }
        catch (Exception ex)
        {
            Debug.WriteLine(ex.ToString());
        }
        var sw = Stopwatch.StartNew();
        foreach (var h in GetPageHashes(args))
        {
            Hashed += h.HashedBlocks;
            Shared += h.SharedAway;
        }
        sw.Stop();

        Debug.WriteLine(String.Format("RunTime {3}, Scanned = {0}, Hashed {1}, Shared {2}", ScanCnt, Hashed, Shared, sw.Elapsed));
    }

    public static IEnumerable<MemPageHash> GetPageHashes(String[] MatchProcNames = null)
    {
        List<string> matchNames = null;
        if (MatchProcNames != null)
            matchNames = MatchProcNames.Select(x => x.ToLower()).ToList();

        var procHndl = IntPtr.Zero;
        var sysinfo = new SYSTEM_INFO();
        NativeMethods.GetSystemInfo(ref sysinfo);
        int Id, PageSize = (int)sysinfo.dwPageSize;
        var ha = SHA256.Create();
        // no longer using the WS info for the entire process at one time, this call may be changed for a more down-level compatible getproc's call
        var procs = GetProcessInfos(WTS_CURRENT_SERVER_HANDLE);
        var ReverseProcOrder = from prox in procs orderby prox.pInfo.ProcessID descending select prox;
        var KnownPages = new Dictionary<long, int>();
        var memBlock = new byte[PageSize];
        var mem = new MEMORY_BASIC_INFORMATION();
        PSAPI_WORKING_SET_EX_INFORMATION[] addRange = null;
        byte[] nullBuf = new byte[sysinfo.dwPageSize];

        foreach (var p in ReverseProcOrder)
        {
            var Regions = new List<MEMORY_BASIC_INFORMATION>();
            var WSInfo = new List<PSAPI_WORKING_SET_EX_INFORMATION>();
            
            var pname = p.pInfo.ProcessName.ToLower();

            if (matchNames != null)
            {
                var glob = matchNames.Where(x => pname.Contains(x));
                if (glob.Count() < 1)
                {
                    Debug.WriteLine("Skipping due to GLOB miss, cant match " + pname + " with search list");
                    continue;
                }
            }
            Id = p.pInfo.ProcessID;
            Debug.WriteLine(String.Format("attempting to open PID {0}", Id));
            try
            {
                try
                {
                    procHndl = NativeMethods.OpenProcess(ProcessAccessFlags.PROCESS_QUERY_INFORMATION | ProcessAccessFlags.PROCESS_VM_READ, true, (uint)Id);
                    if (procHndl == NativeMethods.INVALID_HANDLE_VALUE || procHndl == IntPtr.Zero || Id == Process.GetCurrentProcess().Id)
                    {
                        Debug.WriteLine(String.Format("Skipping due to Handle Invalid {0} or our Proc ID {1}", procHndl == NativeMethods.INVALID_HANDLE_VALUE || procHndl == IntPtr.Zero, Id == Process.GetCurrentProcess().Id));
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(String.Format("Exception in OpenProcess {0}", ex));
                }
                var DebuggerPresent = false;
                CheckRemoteDebuggerPresent(procHndl, ref DebuggerPresent);
                if (DebuggerPresent)
                {
                    Debug.WriteLine("Skipping due to process is currently being debugged and this is somehow a problem why? Were only passively readying, oh well.");
                    continue;
                }

                bool IsWOW = false;
                IsWow64Process(procHndl, out IsWOW);
                HIGHEST_USER_ADDRESS = (IsWOW ? uint.MaxValue : sysinfo.lpMaximumApplicationAddress.ToInt64());

                Debug.WriteLine(String.Format("Adding process to mem state tracking PID {0} {1}", Id, p.pInfo.ProcessName));
                AllMemState.Add(Id, new Dictionary<long, MemState>());
                var name = new StringBuilder(1 << 16);
                int wsCurr = 0, readin = 0, procExitCode = 0;
                const long Address = 0;
                long AddressOffset = 0, startAddr;
                long NextAddress = Address + AddressOffset;
                bool keepGoing, stillRunning;
                int mem_progress = 0;
                keepGoing = true;
                do
                {
                    mem_progress++;
                    if ((mem_progress % 100) == 0)
                        Debug.WriteLine(String.Format("Indexed {0} regions, NextAddress {1:x}", mem_progress, NextAddress));

                    IntPtr wsInfoLength = IntPtr.Zero, workingSetPtr = IntPtr.Zero;
                    var addrPtr = new IntPtr(NextAddress);
                    NativeMethods.VirtualQueryEx(procHndl, addrPtr, ref mem, PageSize);
                    // collect +X regions (TODO: Double check that allocation protect is updated for sub-region page protection changes after initial allocation)
                    if (mem.State == StateEnum.MEM_COMMIT && ((int)mem.AllocationProtect & 0xf0) != 0)
                    {
                        Regions.Add(mem);
                        try
                        {
                            var wsInfoCnt = (mem.RegionSize / PageSize);
                            var wsLen = (0x10 * wsInfoCnt);
                            wsInfoLength = new IntPtr(wsLen);
                            workingSetPtr = Marshal.AllocHGlobal(wsInfoLength);
                            // Determine if any of the pages in the region are shared
                            for (startAddr = mem.BaseAddress, wsCurr = 0; startAddr < (mem.BaseAddress + mem.RegionSize); startAddr += PageSize)
                            {
                                Marshal.WriteInt64(workingSetPtr, wsCurr * 0x10, startAddr);
                                wsCurr++;
                            }
                            if (NativeMethods.QueryWorkingSetEx(procHndl, workingSetPtr, wsInfoLength.ToInt32()))
                            {
                                addRange = GenerateWorkingSetExArray(workingSetPtr, wsCurr);
                                WSInfo.AddRange(addRange);
                            }
                            else
                                WSInfo = null;
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine(String.Format("Exception in processing: {0} {1}", wsInfoLength, ex));
                        }
                        // make sure we clean up memory
                        finally { Marshal.FreeHGlobal(workingSetPtr); }
                    }
                    AddressOffset += (mem.RegionSize >= PageSize ? mem.RegionSize : PageSize);
                    NextAddress = Address + AddressOffset;

                    stillRunning = GetExitCodeProcess(procHndl, out procExitCode);
                    if ((mem.RegionSize == 0) || (NextAddress >= HIGHEST_USER_ADDRESS) || (NextAddress < 0) || !stillRunning || procExitCode != PROCESS_STILL_ACTIVE)
                    {
                        Debug.WriteLine(String.Format("Exiting process region collection due to reached limit of user space {0}  Region Size error {1}", (NextAddress >= HIGHEST_USER_ADDRESS), (mem.RegionSize == 0) || (NextAddress < 0)));
                        keepGoing = false;
                    }
                } while (keepGoing);
                Debug.WriteLine(String.Format("Collected {0} Regions and {1} page WS details", Regions.Count, WSInfo.Count));
                foreach (var region in Regions)
                {
                    short BoundCount = 0;
                    Extract e = null;
                    var rHash = new MemPageHash();
                    var allocPtr = new IntPtr(region.AllocationBase);
                    GetModuleFileNameEx(procHndl, allocPtr, name, 1 << 16);
                    // try to figure out if we have a properly formatted PE
                    try
                    {
                        NativeMethods.ReadProcessMemory(procHndl, allocPtr, memBlock, memBlock.Length, readin);
                    }
                    catch (Exception ex) { Console.Write(ex); }

                    var Base64HdrHash = string.Empty;
                        Byte[] hdrHash = null;

                    e = Extract.IsBlockaPE(memBlock);
                    if (e != null)
                    {
                        e.FileName = name.ToString();
                        // I don't want to recalculate this on the server. ALSO,
                        // just wipe out the directory entries that are in the PE header they may be volatile
                        // consider reversing them later but there's a lot of walking lists for various IMPORT/BOUND/EXPORT/TIMESTAMP checks etc...
                        // this is sort of gravy anyhow as were pretty focused on code integrity, walking these pointers would be good in the long run to 
                        // make sure there's no hidden routines we missed
                        for (int i = e.CheckSumPos; i < e.CheckSumPos + 4; i++)
                            memBlock[i] = 0;
                         
                        // I hate how bound imports sit's in the text section it's not code!
                        int BoundImportsOffset = e.Directories[11].Item1;
                        if(BoundImportsOffset > 0 && BoundImportsOffset < sysinfo.dwPageSize)
                        {
                            bool KeepGoing = true;
                            short curr = 0, offoff = 0;
                            do
                            {
                                offoff += 4;
                                curr = BitConverter.ToInt16(memBlock, BoundImportsOffset + offoff);
                                if (curr == 0)
                                    KeepGoing = false;
                                BoundCount += curr;
                                offoff += 4;

                            } while (KeepGoing);
                        }

                        foreach (var dirEntry in e.Directories)
                            if (dirEntry.Item1 < sysinfo.dwPageSize && ((dirEntry.Item1 + dirEntry.Item2) < sysinfo.dwPageSize))
                                Buffer.BlockCopy(nullBuf, 0, memBlock, dirEntry.Item1, dirEntry.Item2);
                    }
                    if (memBlock != null)
                    {
                        hdrHash = ha.ComputeHash(memBlock);
                        Base64HdrHash = Convert.ToBase64String(hdrHash);
                    }
                    // save rHash in state table 
                    AllMemState[Id][region.AllocationBase] = new MemState() { e = e, pHash = rHash };
                    // permute extra details
                    rHash.ModuleName = name.ToString();
                    rHash.Id = p.pInfo.ProcessID;
                    rHash.ProcessName = p.pInfo.ProcessName;
                    rHash.AllocationBase = region.AllocationBase;
                    rHash.BaseAddress = region.BaseAddress;
                    rHash.Size = region.RegionSize;
                    rHash.HdrHash = Base64HdrHash;
                    if (e != null)
                    {
                        rHash.TimeDateStamp = e.TimeStamp;
                        rHash.ImageSize = (uint)e.SizeOfImage;
                    }
                    // we do not have range info so we have todo this expensive check 
                    // this is really to keep the memory pressure low more than anything
                    if (WSInfo == null)
                    {
                        for (long addr = region.BaseAddress; addr < region.BaseAddress + region.RegionSize; addr += PageSize)
                        {
                            if (!NativeMethods.ReadProcessMemory(procHndl, new IntPtr(addr), memBlock, memBlock.Length, readin))
                            {
                                rHash.HashSet.Add(new PageHashBlock() { Address = addr, Hash = "***BAD_READ***" });
                            }
                            else
                            {
                                if(e != null && BoundCount > 0 && ((addr - region.AllocationBase) == e.BaseOfCode))
                                    Buffer.BlockCopy(nullBuf, 0, memBlock, 0, BoundCount);
                                
                                var ph = new PageHashBlock() { Address = addr, Hash = Convert.ToBase64String(ha.ComputeHash(memBlock)) };

                                var IsUniq = from hashedMem in AllMemState.Values.AsParallel()
                                             from hashes in hashedMem.Values
                                             from blocks in hashes.pHash.HashSet
                                             where blocks.Hash.Equals(ph.Hash)
                                             select blocks;
                                if (IsUniq.Count() < 1)
                                {
                                    rHash.HashSet.Add(ph);
                                    rHash.HashedBlocks++;
                                }
                                else
                                    rHash.SharedAway++;
                            }
                        }
                        if (rHash.HashSet.Count > 0)
                        {
                            Debug.WriteLine(String.Format("Yielding region information for {2} Base 0x{0:x} - Limit 0x{1:x} Hashed pages count {3}, Gaps in region 0x{4:x} bytes  (No WSQuery Info)", rHash.BaseAddress, rHash.Size, rHash.ModuleName, rHash.HashSet.Count, region.RegionSize - (rHash.HashSet.Count * PageSize)));
                            yield return rHash;
                        }
                    }
                    else
                    {
                        // if we have "new" executable pages scan them
                        foreach (var addr in from range in WSInfo
                                             where
                                 ((range.VirtualAddress == region.BaseAddress) && ((int)region.AllocationProtect & 0xf) != 0) 
                                 || 
                                 ((range.VirtualAddress >= region.BaseAddress &&
                                 range.VirtualAddress < (region.BaseAddress + region.RegionSize)) &&
                                 ((range.WorkingSetInfo.Block1.Protection & 0xf0) != 0))
                                             select range)
                        {
                            if (!KnownPages.ContainsKey(addr.VirtualAddress))
                            {
                                // This is a shared page we have never seen before, add it to this index so we can avoid scanning it next time we see it
                                if (addr.WorkingSetInfo.Block1.ShareCnt != 0)
                                    KnownPages.Add(addr.VirtualAddress, Id);

                                // scan this single page
                                if (!NativeMethods.ReadProcessMemory(procHndl, new IntPtr(addr.VirtualAddress), memBlock, memBlock.Length, readin))
                                    rHash.HashSet.Add(new PageHashBlock() { Address = addr.VirtualAddress, Hash = "***BAD_READ***" });
                                else
                                {
                                    if (e != null && BoundCount > 0 && ((addr.VirtualAddress - region.AllocationBase) == e.BaseOfCode))
                                        Buffer.BlockCopy(nullBuf, 0, memBlock, 0, BoundCount > memBlock.Length ? memBlock.Length : BoundCount);

                                    rHash.HashedBlocks++;
                                    rHash.HashSet.Add(new PageHashBlock() { Address = addr.VirtualAddress, Hash = Convert.ToBase64String(ha.ComputeHash(memBlock)) });
                                }
                            }
                            else
                                rHash.SharedAway++;
                        }
                        if (rHash.HashSet.Count > 0)
                        {
                            Debug.WriteLine(String.Format("Yielding region information for {2} Base 0x{0:x} - Limit 0x{1:x} Hashed pages count {3}, Gaps in region 0x{4:x} (Used WS Query Info)", rHash.BaseAddress, rHash.Size, rHash.ModuleName, rHash.HashSet.Count, region.RegionSize - (rHash.HashSet.Count * PageSize)));
                            yield return rHash;
                        }
                    }
                    TotShare += rHash.SharedAway;
                    ScanCnt += rHash.HashedBlocks;
                }
            }
            finally { CloseHandle(procHndl); }
        }
    }
    #region PINVOKE
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
        var pSaveMem = IntPtr.Zero;
        SessionInfo[] rv = null;
        try
        {
            IntPtr pProcessInfo = IntPtr.Zero;
            var processCount = 0;
            var useProcessesExStructure = new IntPtr(1);
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
                        var name = new StringBuilder();
                        var cchName = (uint)name.Capacity;
                        SID_NAME_USE sidUse;
                        var referencedDomainName = new StringBuilder();
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
        catch (Exception ex)
        {
            Debug.WriteLine(ex.Message + "\r\n" + Marshal.GetLastWin32Error());
        }
        finally
        {
            if (pSaveMem != IntPtr.Zero)
                WTSFreeMemory(pSaveMem);
        }
        return rv;
    }
    const int PROCESS_STILL_ACTIVE = 259;
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out int lpExitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

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
    public static extern bool QueryWorkingSetEx(IntPtr hProcess, IntPtr info, int size);
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
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
        private static BLOCK_EX_INVALID Invalid;
        public bool IsValid { get { return (Bits & 1) != 0; } }
        public int ShareCnt { get { return (int)(Bits >> Valid) & 0x7; } }
        public int Protection { get { return (int)(Bits >> ShareCount + Valid) & 0x7FF; } }
        public bool IsShareable { get { return (Bits >> (Win32Protection + ShareCount + Valid) & 1) != 0; } }
        public int NodeId { get { return (int)(Bits >> Shareable + Win32Protection + ShareCount + Valid) & 0x3f; } }
        public bool IsLocked { get { return (Bits >> (Node + Shareable + Win32Protection + ShareCount + Valid) & 1) != 0; } }
        public bool IsLargePage { get { return Bits >> (Locked + Node + Shareable + Win32Protection + ShareCount + Valid) != 0; } }
        public int ReservedBits { get { return (int)Bits >> (LargePage + Locked + Node + Shareable + Win32Protection + ShareCount + Valid); } }
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
        public int ReservedBits0 { get { return (int)(Bits >> 1) & 0x3FFF; } }
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
        public override string ToString()
        {
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
        public Int32 SessionID;         // The Remote Desktop Services session identifier for the session associated with the process.
        public Int32 ProcessID;         // The process identifier that uniquely identifies the process on the RD Session Host server.
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ProcessName;      // A pointer to a null-terminated string that contains the name of the executable file associated with the process.
        public IntPtr UserSid;          // A pointer to the user security identifiers (SIDs) in the primary access token of the process. 
        public Int32 NumberOfThreads;   // The number of threads in the process.
        public Int32 HandleCount;       // The number of handles in the process.
        public Int32 PagefileUsage;     // The page file usage of the process, in bytes.
        public Int32 PeakPagefileUsage; // The peak page file usage of the process, in bytes.
        public Int32 WorkingSetSize;    // The working set size of the process, in bytes.
        public Int32 PeakWorkingSetSize;// The peak working set size of the process, in bytes.
        public long UserTime;   // The amount of time, in milliseconds, the process has been running in user mode.
        public long KernelTime;// The amount of time, in milliseconds, the process has been running in kernel mode.
    }
    public enum SID_NAME_USE
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
    #endregion
}
#region PE Support
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
    public override string ToString()
    {
        return String.Format("{0} - VBase {1:X}:{VirtualSize:X} - File {2:X}:{3:X} - R:{4},W:{5},X:{6},S:{7},D:{8}",
            Name, VirtualAddress, RawFilePointer, RawFileSize, IsRead, IsWrite, IsExec, IsShared, IsDiscard);
    }
}
// Extract compiles a local reloc set that can be used when dumping memory to recover identical files 
public class Extract
{
    public int rID, secOff, CheckSumPos;
    public bool Is64, IsCLR;
    public ulong ImageBase;
    public string Hash, FileName;
    public long VA, ImageBaseOffset;
    public uint TimeStamp, SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders, RelocPos, RelocSize, ClrAddress, ClrSize, EntryPoint, BaseOfCode, CheckSum;
    public short NumberOfSections;
    public List<Tuple<int, int>> Directories;
    // maybe ordered list would emit better errors for people
    public List<MiniSection> Sections;
    public override string ToString()
    {
        var sb = new StringBuilder(String.Format("{0}**PE FILE** \t-\t-\t Date   [{1:X8}]{2}*DebugPos* \t-\t-\t Offset [{3:X8}] \t-\t Size [{4:X8}] {5}*Base*  \t-\t-\t Offset [{6:X16}] -\t Size [{7:X8}]{8}",
            Environment.NewLine, TimeStamp, Environment.NewLine, ImageBase, SizeOfImage, Environment.NewLine));
        foreach (var s in Sections)
            sb.Append(String.Format("[{0}] \t-\t-\t Offset [{1:X8}] \t-\t Size [{2:X8}]{3}",
                s.Name.PadRight(8), s.VirtualAddress, s.VirtualSize, Environment.NewLine));
        sb.AppendLine();
        return sb.ToString();
    }
    public static Extract IsBlockaPE(byte[] block, int blockOffset = 0)
    {
        Extract extracted_struct = new Extract();
        if (block[blockOffset] != 0x4d || block[blockOffset + 1] != 0x5a) return null;
        var headerOffset = BitConverter.ToInt32(block, blockOffset + 0x3C);
        // bad probably
        if (headerOffset > 3000) return null;
        if (BitConverter.ToInt32(block, blockOffset + headerOffset) != 0x00004550) return null;
        var pos = blockOffset + headerOffset + 6;
        extracted_struct.NumberOfSections = BitConverter.ToInt16(block, pos); pos += 2;
        extracted_struct.Sections = new List<MiniSection>();
        extracted_struct.TimeStamp = BitConverter.ToUInt32(block, pos); pos += 4;
        pos += 8;
        extracted_struct.secOff = BitConverter.ToUInt16(block, pos); pos += 2;
        pos += 2;
        var magic = BitConverter.ToUInt16(block, pos); pos += 2;
        // sizeofcode, sizeofinit, sizeofuninit, 
        pos += 14;
        extracted_struct.EntryPoint = BitConverter.ToUInt32(block, pos); pos += 4;
        extracted_struct.BaseOfCode = BitConverter.ToUInt32(block, pos); pos += 4;

        if (extracted_struct.Is64)
        {
            // we wan't this to be page aligned to typical small page size
            extracted_struct.ImageBaseOffset = pos & 0xfff;
            extracted_struct.ImageBase = BitConverter.ToUInt64(block, pos); pos += 8;
        }
        else
        {
            // baseofdata
            pos += 4;
            // imagebase
            extracted_struct.ImageBaseOffset = pos & 0xfff;
            extracted_struct.ImageBase = BitConverter.ToUInt32(block, pos); pos += 4;
        }
        extracted_struct.SectionAlignment = BitConverter.ToUInt32(block, pos); pos += 4;
        extracted_struct.FileAlignment = BitConverter.ToUInt32(block, pos); pos += 4;
        pos += 16;
        extracted_struct.SizeOfImage = BitConverter.ToUInt32(block, pos); pos += 4;
        extracted_struct.SizeOfHeaders = BitConverter.ToUInt32(block, pos); pos += 4;
        // checksum
        extracted_struct.CheckSumPos = pos;
        extracted_struct.CheckSum = BitConverter.ToUInt32(block, pos); pos += 4;
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

        extracted_struct.Directories = new List<Tuple<int, int>>(16);
        // collect a list of all directories in a table
        for (int i=0; i<0x10; i++)
            extracted_struct.Directories.Add(Tuple.Create<int, int>(BitConverter.ToInt32(block, pos + (i * 8)), BitConverter.ToInt32(block, pos + (i * 8) + 4)));

        extracted_struct.ClrAddress = (uint) extracted_struct.Directories[0xf].Item1;
        extracted_struct.ClrSize = (uint) extracted_struct.Directories[0xf].Item2;

        if (extracted_struct.ClrAddress != 0)
            extracted_struct.IsCLR = true;

        var CurrEnd = extracted_struct.SizeOfHeaders;
        /// implicit section for header
        extracted_struct.Sections.Add(new MiniSection { VirtualSize = CurrEnd, RawFileSize = CurrEnd, RawFilePointer = 0, VirtualAddress = 0, Name = ".PEHeader", Characteristics = 0x20000000 });
        // get to sections
        pos = blockOffset + headerOffset + (extracted_struct.Is64 ? 0x108 : 0xF8);
        for (int i = 0; i < extracted_struct.NumberOfSections; i++)
        {
            var rawStr = new String(new char[8] { (char)block[pos], (char)block[pos + 1], (char)block[pos + 2], (char)block[pos + 3], (char)block[pos + 4], (char)block[pos + 5], (char)block[pos + 6], (char)block[pos + 7] }); pos += 8;
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
#endregion
}


"@
    }
    if($ElevatePastAdmin)
    {
        [System.Diagnostics.process]::EnterDebugMode()
        Get-System 
    }

	$codeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider
	$location = [PsObject].Assembly.Location
	$compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
	$assemblyRange = @("System.dll", "System.Core.dll", $location)
	$compileParams.ReferencedAssemblies.AddRange($assemblyRange)
    $compileParams.GenerateInMemory = $True
    $compileParams.TreatWarningsAsErrors = $false
	[void]$codeProvider.CompileAssemblyFromSource($compileParams, $Code)
    
    # Warnings about unused variables (they are used but only when debugging)
	Add-Type -TypeDefinition $Code -Language CSharp 
	foreach ($h in [MemTest.NativeMethods]::GetPageHashes($ProcNameGlob))
	{
		$h | ConvertTo-Json
	}
	return
}

$code2 =
@"
namespace MemTest
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.IO;
    /*
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
    */
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

$codeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider

$location = [PsObject].Assembly.Location
$compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
$assemblyRange = @("System.dll", $location)
$compileParams.ReferencedAssemblies.AddRange($assemblyRange)
$compileParams.GenerateInMemory = $True
[void]$codeProvider.CompileAssemblyFromSource($compileParams, $code2)
Add-Type -TypeDefinition $code2 -Language CSharp

# Global thread safe collection
$global:readyFiles = New-Object 'System.Collections.Concurrent.ConcurrentStack[pscustomobject]'

$uri = "https://pdb2json.azurewebsites.net/api/PageHash/x"
$s = New-PSSession -ComputerName $serverName -Credential $testCred 
$job = Invoke-Command -Session $s -ScriptBlock ${function:blockfun} -ArgumentList $ProcNameGlob -AsJob 

. .\Invoke-Parallel.ps1
do
{
	$output = Receive-Job -Job $job
	$output | Invoke-Parallel -Throttle $MaxThreads -MaxQueue $MaxThreads -ImportVariables  { 
		$body = $_
		#send web request for hash validation
		$content = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "application/json"  -UseBasicParsing

		if ($content -eq $null)	{
			continue
		}
		$rv = $content | ConvertFrom-Json

		# save test case and results
		$hashAction = [pscustomobject]@{
			Test	   = $body
			Result	   = $rv
		}
		[void]$global:readyFiles.Push($hashAction)
		if (($global:readyFiles.Count % 100) -eq 0)
		{
			Write-Host "Result count: " $global:readyFiles.Count
		}
	}
} while ($job.State -eq "Running")

$s | Remove-PSSession 
Write-Host "Done. Collected " + $global:readyFiles.Count + " results."

$items = $global:readyFiles.ToArray()

foreach ($item in $items)
{
	$itemX = $item.Test | ConvertFrom-Json
    $ProcessName = $itemX.ProcessName
    $ErrorActionPreference = "SilentlyContinue"
    $Module = Remove-InvalidFileNameChars($itemX.ModuleName.Split([System.IO.Path]::DirectorySeparatorChar)|Select-Object -Last 1)
	$Name = $ProcessName + " : " + $Module
	$Size = $itemX.Size
	$checkedBlocks = $itemX.HashedBlocks
	$validatedBlocks = 0
	foreach ($result in $item.Result)
	{
		if ($result.HashCheckEquivalant)
		{
			$validatedBlocks++
		}
	}
    if($checkedBlocks -lt 1) {
        continue
    }
    $ratio = ($validatedBlocks / $checkedBlocks)
	$Heat = 1.0 - $ratio
	$percentValid = $ratio * 100.0

    $baseAddr = $itemX.BaseAddress
    $fullName = $Name + " " + (Select -InputObject $itemX Id)

    Add-Member -NotePropertyName Size -NotePropertyValue $Size -InputObject $item
	Add-Member -NotePropertyName FullName -NotePropertyValue $fullName -InputObject $item
    Add-Member -NotePropertyName BaseAddress -NotePropertyValue $baseAddr -InputObject $item
    Add-Member -NotePropertyName Struct -NotePropertyValue $itemX -InputObject $item
    Add-Member -NotePropertyName Id -NotePropertyValue $itemX.Id -InputObject $item
	Add-Member -NotePropertyName Module -NotePropertyValue $Module -InputObject $item
	Add-Member -NotePropertyName Name -NotePropertyValue $Name -InputObject $item
	Add-Member -NotePropertyName ProcessName -NotePropertyValue $ProcessName -InputObject $item
	Add-Member -NotePropertyName Heat -NotePropertyValue $Heat -InputObject $item
	Add-Member -NotePropertyName PercentValid -NotePropertyValue $percentValid -InputObject $item
	Add-Member -NotePropertyName TotalChecked -NotePropertyValue $checkedBlocks -InputObject $item
	Add-Member -NotePropertyName TotalValidated -NotePropertyValue $validatedBlocks -InputObject $item
}

if($GUIOutput -eq $true) {
	#Customized version of TreeMap
	
	#Build hierarchical view of processes
	$d = New-Object 'system.collections.generic.dictionary[int,pscustomobject]'
	
	foreach ($item in $items)
	{
        if($item.TotalChecked -lt 1)
        {
            continue
        }

		if($d.ContainsKey($item.Id))
		{
            $process = $d[$item.Id]


            if($item.TotalChecked -eq 0)
            {
                continue   
            }            

			$process.TotalChecked += $item.TotalChecked
			$process.TotalValidated += $item.TotalValidated

            $ratio = ($process.TotalValidated / $process.TotalChecked)
		    $process.PercentValid=$ratio * 100.0
		    $process.Heat=1.0 - $ratio

			[void]$process.Modules.Add($item)

		} else {    
            $ratio = ($item.TotalValidated / $item.TotalChecked)
            
			$Process = [pscustomobject]@{
				Name   = $item.ProcessName
				Id	   = $item.Id
				TotalChecked = $item.TotalChecked
				TotalValidated = $item.TotalValidated
                FullName = $item.ProcessName  + " " + $item.Id
				PercentValid = $ratio * 100.0
				Heat = 1.0 - $ratio

				Modules = New-Object -TypeName 'System.Collections.ArrayList'; 
			}
			[void]$Process.Modules.Add($item)
			[void]$d.Add($item.Id, $Process)
		}
	}

	#Organize UI dependencies
	Import-Module ShowUI
	. .\Out-SquarifiedTreeMap.ps1
	
	$Procs  = [pscustomobject]@{
			Label = "ALL PROCS"
			Children  = $d.Values
	}
	foreach($p in $d.Values) {
		$Label = $p.Name + " " + $p.Id
        Add-Member -NotePropertyName Label -NotePropertyValue $Label -InputObject $p
        Add-Member -NotePropertyName Children -NotePropertyValue $p.Modules -InputObject $p
        Add-Member -Force -NotePropertyName Size -NotePropertyValue ($p.TotalChecked * 4096) -InputObject $p

		foreach($module in $p.Modules) 
		{
			$modChildren  = New-Object -TypeName 'System.Collections.ArrayList'; 
            $baseAddr = [string]::Format("{0:x}", $module.BaseAddress)
			$ModLabel = $module.Module + " " + $baseAddr
            Add-Member -NotePropertyName Label -NotePropertyValue $ModLabel -InputObject $module
            $modSize = $module.TotalChecked * 4096
            Add-Member -NotePropertyName Size -NotePropertyValue $modSize -InputObject $module

			foreach($hash in $module.Struct.HashSet) 
			{
				$aHeat = 1.0
				foreach($r in $module.Result)
				{
					if($r.Address -eq $hash.Address)
					{
						if($r.HashCheckEquivalant -eq "True")
						{
							$aHeat = 0.0
						}
						break;
					}
                }
                $BlockPercentValid = (1.0 - $aHeat) * 100.0
                $BlockFullName = $Label + " " + $ModLabel + " RVA: " + ($hash.Address - $module.BaseAddress).ToString("x")
				$block = [pscustomobject]@{
					Label="BLOCK " + $hash.Address.ToString("x")
                    Size = 4096
                    Heat = $aHeat
                    PercentValid=$BlockPercentValid
					Children=New-Object -TypeName 'System.Collections.ArrayList'
                }

                Add-Member -NotePropertyName FullName -NotePropertyValue $BlockFullName -InputObject $block
				[void]$modChildren.Add($block)					
            }

            Add-Member -NotePropertyName Children -NotePropertyValue $modChildren -InputObject $module
		}
    }
    $Procs.Children.Count.ToString() + " Processes scanned."
    
    $Tooltip = {
@"
Name = $($This.LabelProperty)
FullName = $($This.ObjectData.FullName)
PercentValid = $($This.ObjectData.PercentValid)
Size = $($This.ObjectData.Size) 
"@
    }
    Out-SquarifiedTreeMap -InputObject $Procs.Children -Width 1024 -Height 768 -DataProperty Size -HeatmapProperty Heat -MaxHeatMapSize 1.0 -LabelProperty Label -Tooltip $Tooltip -ShowLabel {"$($This.LabelProperty)"} | Show-UI
}
