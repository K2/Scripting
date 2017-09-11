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
	[String]$ProcNameGlob = "",
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

function blockfun ($ProcNameGlob) {

    # Embed Get-System in here from PowerSploit makes life easier, I also modified it a bit to make life easier ;)
        function Get-System {
    <#
        .SYNOPSIS

            GetSystem functionality inspired by Meterpreter's getsystem.
            'NamedPipe' impersonation doesn't need SeDebugPrivilege but does create
            a service, 'Token' duplications a SYSTEM token but needs SeDebugPrivilege.
            NOTE: if running PowerShell 2.0, start powershell.exe with '-STA' to ensure
            token duplication works correctly.

            PowerSploit Function: Get-System
            Author: @harmj0y, @mattifestation
            License: BSD 3-Clause
            Required Dependencies: None
            Optional Dependencies: None

        .PARAMETER Technique

            The technique to use, 'NamedPipe' or 'Token'.

        .PARAMETER ServiceName

            The name of the service used with named pipe impersonation, defaults to 'TestSVC'.

        .PARAMETER PipeName

            The name of the named pipe used with named pipe impersonation, defaults to 'TestSVC'.

        .PARAMETER RevToSelf
        
            Reverts the current thread privileges.

        .PARAMETER WhoAmI

            Switch. Display the credentials for the current PowerShell thread.

        .EXAMPLE
            
            PS> Get-System

            Uses named impersonate to elevate the current thread token to SYSTEM.

        .EXAMPLE
            
            PS> Get-System -ServiceName 'PrivescSvc' -PipeName 'secret'

            Uses named impersonate to elevate the current thread token to SYSTEM
            with a custom service and pipe name.

        .EXAMPLE
            
            PS> Get-System -Technique Token

            Uses token duplication to elevate the current thread token to SYSTEM.

        .EXAMPLE
            
            PS> Get-System -WhoAmI

            Displays the credentials for the current thread.

        .EXAMPLE
            
            PS> Get-System -RevToSelf

            Reverts the current thread privileges.

        .LINK
        
            https://github.com/rapid7/meterpreter/blob/2a891a79001fc43cb25475cc43bced9449e7dc37/source/extensions/priv/server/elevate/namedpipe.c
            https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot
            http://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
            http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/
    #>
        [CmdletBinding(DefaultParameterSetName = 'NamedPipe')]
        param(
            [Parameter(ParameterSetName = "NamedPipe")]
            [Parameter(ParameterSetName = "Token")]
            [String]
            [ValidateSet("NamedPipe", "Token")]
            $Technique = 'NamedPipe',

            [Parameter(ParameterSetName = "NamedPipe")]
            [String]
            $ServiceName = 'TestSVC',

            [Parameter(ParameterSetName = "NamedPipe")]
            [String]
            $PipeName = 'TestSVC',

            [Parameter(ParameterSetName = "RevToSelf")]
            [Switch]
            $RevToSelf,

            [Parameter(ParameterSetName = "WhoAmI")]
            [Switch]
            $WhoAmI
        )

        $ErrorActionPreference = "Stop"

        # from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
        function Local:Get-DelegateType
        {
            Param
            (
                [OutputType([Type])]
                
                [Parameter( Position = 0)]
                [Type[]]
                $Parameters = (New-Object Type[](0)),
                
                [Parameter( Position = 1 )]
                [Type]
                $ReturnType = [Void]
            )

            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
            $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
            $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
            $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
            $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
            $MethodBuilder.SetImplementationFlags('Runtime, Managed')
            
            Write-Output $TypeBuilder.CreateType()
        }

        # from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
        function Local:Get-ProcAddress
        {
            Param
            (
                [OutputType([IntPtr])]
            
                [Parameter( Position = 0, Mandatory = $True )]
                [String]
                $Module,
                
                [Parameter( Position = 1, Mandatory = $True )]
                [String]
                $Procedure
            )

            # Get a reference to System.dll in the GAC
            $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
            $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
            # Get a reference to the GetModuleHandle and GetProcAddress methods
            $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
            $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
            # Get a handle to the module specified
            $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
            $tmpPtr = New-Object IntPtr
            $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
            
            # Return the address of the function
            Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
        }

        # performs named pipe impersonation to elevate to SYSTEM without needing
        #   SeDebugPrivilege
        function Local:Get-SystemNamedPipe {
            param(
                [String]
                $ServiceName = "TestSVC",

                [String]
                $PipeName = "TestSVC"
            )

            $Command = "%COMSPEC% /C start %COMSPEC% /C `"timeout /t 3 >nul&&echo $PipeName > \\.\pipe\$PipeName`""

            Add-Type -Assembly System.Core

            # create the named pipe used for impersonation and set appropriate permissions
            $PipeSecurity = New-Object System.IO.Pipes.PipeSecurity
            $AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "Everyone", "ReadWrite", "Allow" )
            $PipeSecurity.AddAccessRule($AccessRule)
            $Pipe = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName,"InOut",100, "Byte", "None", 1024, 1024, $PipeSecurity)

            $PipeHandle = $Pipe.SafePipeHandle.DangerousGetHandle()

            # Declare/setup all the needed API function
            #   adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html 
            $ImpersonateNamedPipeClientAddr = Get-ProcAddress Advapi32.dll ImpersonateNamedPipeClient
            $ImpersonateNamedPipeClientDelegate = Get-DelegateType @( [Int] ) ([Int])
            $ImpersonateNamedPipeClient = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateNamedPipeClientAddr, $ImpersonateNamedPipeClientDelegate)

            $CloseServiceHandleAddr = Get-ProcAddress Advapi32.dll CloseServiceHandle
            $CloseServiceHandleDelegate = Get-DelegateType @( [IntPtr] ) ([Int])
            $CloseServiceHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseServiceHandleAddr, $CloseServiceHandleDelegate)

            $OpenSCManagerAAddr = Get-ProcAddress Advapi32.dll OpenSCManagerA
            $OpenSCManagerADelegate = Get-DelegateType @( [String], [String], [Int]) ([IntPtr])
            $OpenSCManagerA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenSCManagerAAddr, $OpenSCManagerADelegate)
            
            $OpenServiceAAddr = Get-ProcAddress Advapi32.dll OpenServiceA
            $OpenServiceADelegate = Get-DelegateType @( [IntPtr], [String], [Int]) ([IntPtr])
            $OpenServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenServiceAAddr, $OpenServiceADelegate)
        
            $CreateServiceAAddr = Get-ProcAddress Advapi32.dll CreateServiceA
            $CreateServiceADelegate = Get-DelegateType @( [IntPtr], [String], [String], [Int], [Int], [Int], [Int], [String], [String], [Int], [Int], [Int], [Int]) ([IntPtr])
            $CreateServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateServiceAAddr, $CreateServiceADelegate)

            $StartServiceAAddr = Get-ProcAddress Advapi32.dll StartServiceA
            $StartServiceADelegate = Get-DelegateType @( [IntPtr], [Int], [Int]) ([IntPtr])
            $StartServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StartServiceAAddr, $StartServiceADelegate)

            $DeleteServiceAddr = Get-ProcAddress Advapi32.dll DeleteService
            $DeleteServiceDelegate = Get-DelegateType @( [IntPtr] ) ([IntPtr])
            $DeleteService = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DeleteServiceAddr, $DeleteServiceDelegate)

            $GetLastErrorAddr = Get-ProcAddress Kernel32.dll GetLastError
            $GetLastErrorDelegate = Get-DelegateType @() ([Int])
            $GetLastError = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetLastErrorAddr, $GetLastErrorDelegate)

            # Step 1 - OpenSCManager()
            # 0xF003F = SC_MANAGER_ALL_ACCESS
            #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
            Write-Verbose "Opening service manager"
            $ManagerHandle = $OpenSCManagerA.Invoke("\\localhost", "ServicesActive", 0xF003F)
            Write-Verbose "Service manager handle: $ManagerHandle"

            # if we get a non-zero handle back, everything was successful
            if ($ManagerHandle -and ($ManagerHandle -ne 0)) {

                # Step 2 - CreateService()
                # 0xF003F = SC_MANAGER_ALL_ACCESS
                # 0x10 = SERVICE_WIN32_OWN_PROCESS
                # 0x3 = SERVICE_DEMAND_START
                # 0x1 = SERVICE_ERROR_NORMAL
                Write-Verbose "Creating new service: '$ServiceName'"
                try {
                    $ServiceHandle = $CreateServiceA.Invoke($ManagerHandle, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, $Command, $null, $null, $null, $null, $null)
                    $err = $GetLastError.Invoke()
                }
                catch {
                    Write-Warning "Error creating service : $_"
                    $ServiceHandle = 0
                }
                Write-Verbose "CreateServiceA Handle: $ServiceHandle"

                if ($ServiceHandle -and ($ServiceHandle -ne 0)) {
                    $Success = $True
                    Write-Verbose "Service successfully created"

                    # Step 3 - CloseServiceHandle() for the service handle
                    Write-Verbose "Closing service handle"
                    $Null = $CloseServiceHandle.Invoke($ServiceHandle)

                    # Step 4 - OpenService()
                    Write-Verbose "Opening the service '$ServiceName'"
                    $ServiceHandle = $OpenServiceA.Invoke($ManagerHandle, $ServiceName, 0xF003F)
                    Write-Verbose "OpenServiceA handle: $ServiceHandle"

                    if ($ServiceHandle -and ($ServiceHandle -ne 0)){

                        # Step 5 - StartService()
                        Write-Verbose "Starting the service"
                        $val = $StartServiceA.Invoke($ServiceHandle, $null, $null)
                        $err = $GetLastError.Invoke()

                        # if we successfully started the service, let it breathe and then delete it
                        if ($val -ne 0){
                            Write-Verbose "Service successfully started"
                            # breathe for a second
                            Start-Sleep -s 1
                        }
                        else{
                            if ($err -eq 1053){
                                Write-Verbose "Command didn't respond to start"
                            }
                            else{
                                Write-Warning "StartService failed, LastError: $err"
                            }
                            # breathe for a second
                            Start-Sleep -s 1
                        }

                        # start cleanup
                        # Step 6 - DeleteService()
                        Write-Verbose "Deleting the service '$ServiceName'"
                        $val = $DeleteService.invoke($ServiceHandle)
                        $err = $GetLastError.Invoke()

                        if ($val -eq 0){
                            Write-Warning "DeleteService failed, LastError: $err"
                        }
                        else{
                            Write-Verbose "Service successfully deleted"
                        }
                    
                        # Step 7 - CloseServiceHandle() for the service handle 
                        Write-Verbose "Closing the service handle"
                        $val = $CloseServiceHandle.Invoke($ServiceHandle)
                        Write-Verbose "Service handle closed off"
                    }
                    else {
                        Write-Warning "[!] OpenServiceA failed, LastError: $err"
                    }
                }

                else {
                    Write-Warning "[!] CreateService failed, LastError: $err"
                }

                # final cleanup - close off the manager handle
                Write-Verbose "Closing the manager handle"
                $Null = $CloseServiceHandle.Invoke($ManagerHandle)
            }
            else {
                # error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
                Write-Warning "[!] OpenSCManager failed, LastError: $err"
            }

            if($Success) {
                Write-Verbose "Waiting for pipe connection"
                $Pipe.WaitForConnection()

                $Null = (New-Object System.IO.StreamReader($Pipe)).ReadToEnd()

                $Out = $ImpersonateNamedPipeClient.Invoke([Int]$PipeHandle)
                Write-Verbose "ImpersonateNamedPipeClient: $Out"
            }

            # clocse off the named pipe
            $Pipe.Dispose()
        }

        # performs token duplication to elevate to SYSTEM
        #   needs SeDebugPrivilege
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

        elseif($PSBoundParameters['RevToSelf']) {
            $RevertToSelfAddr = Get-ProcAddress advapi32.dll RevertToSelf
            $RevertToSelfDelegate = Get-DelegateType @() ([Bool])
            $RevertToSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)

            $RetVal = $RevertToSelf.Invoke()
            if($RetVal) {
                Write-Output "RevertToSelf successful."
            }
            else {
                Write-Warning "RevertToSelf failed."
            }
            Write-Output "Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
        }

        else {
            if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
                Write-Error "Script must be run as administrator" -ErrorAction Stop
            }

            if($Technique -eq 'NamedPipe') {
                # if we're using named pipe impersonation with a service
                Get-SystemNamedPipe -ServiceName $ServiceName -PipeName $PipeName
            }
            else {
                # otherwise use token duplication
                Get-SystemToken
            }
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
            }
            else
            {
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
        public static Dictionary<int, Dictionary<long, MemState>> AllMemState = new Dictionary<int, Dictionary<long, MemState>>();
        public class MemState
        {
            public long Address;
            public Extract e;
            public MemPageHash pHash;
        }
#if FALSE
        static void Main(string[] args)
		{
			Stopwatch sw = Stopwatch.StartNew();
			long Hashed = 0, Shared = 0;
			int lastId = 0;
			foreach(var h in GetPageHashes())
			{
				//Console.WriteLine(h);
				Hashed += h.HashedBlocks;
				Shared += h.SharedAway;
#if DEBUG
				if (lastId != h.Id)
				{
					//Console.WriteLine($"{Hashed} hashed blocks, {Shared} shared.  {sw.Elapsed} ({(Hashed * 100.0) / sw.Elapsed.TotalSeconds:N3})");
					lastId = h.Id;
				}
#endif
			}
			Console.WriteLine("Scanned = " + ScanCnt);
		}
#endif
        static long ScanCnt = 0, TotShare = 0;
        static long HIGHEST_USER_ADDRESS = 0x7ffffffeffff;
        public static IEnumerable<MemPageHash> GetPageHashes(String MatchProcName = null)
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

            var mem = new MEMORY_BASIC_INFORMATION();
            //var WSInfo = new List<PSAPI_WORKING_SET_EX_INFORMATION>();
            PSAPI_WORKING_SET_EX_INFORMATION[] addRange = null;
            var Regions = new List<MEMORY_BASIC_INFORMATION>();

            foreach (var p in procs)
            {
                try
                {
                    try
                    {
                        bool DebuggerPresent = false;
                        workingSetPtr = IntPtr.Zero;

                        if (!string.IsNullOrWhiteSpace(MatchProcName))
                            if (!p.pInfo.ProcessName.ToLower().Contains(MatchProcName.ToLower()))
                                continue;

                        Id = p.pInfo.ProcessID;
                        Console.WriteLine(String.Format("attempting to open PID {0}", Id));

                        procHndl = NativeMethods.OpenProcess(ProcessAccessFlags.PROCESS_QUERY_INFORMATION | ProcessAccessFlags.PROCESS_VM_READ, true, (uint)Id);

                        if (procHndl == NativeMethods.INVALID_HANDLE_VALUE || procHndl == IntPtr.Zero || Id == Process.GetCurrentProcess().Id)
                            continue;

                        CheckRemoteDebuggerPresent(procHndl, ref DebuggerPresent);
                        if (DebuggerPresent)
                            continue;

                        AllMemState.Add(Id, new Dictionary<long, MemState>());

                        var memInfo = (uint)p.pInfo.PeakWorkingSetSize;

                        var wsInfoCnt = (memInfo / 0x400);
                        wsLen = (0x10 * wsInfoCnt);

                        wsInfoLength = new IntPtr(wsLen);
                        workingSetPtr = Marshal.AllocHGlobal(wsInfoLength);
                        var baseAddr = workingSetPtr.ToInt64();

                        bool keepGoing = true;
                        int wsCurr = 0;
                        long AddressOffset = 0;
                        long Address = 0;
                        long NextAddress = Address + AddressOffset;
                        do
                        {
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
                            if (mem.RegionSize < 4096)
                                AddressOffset += 4096;
                            NextAddress = Address + AddressOffset;

                            if ((mem.RegionSize == 0) || (NextAddress >= HIGHEST_USER_ADDRESS) || (NextAddress < 0))
                                keepGoing = false;

                        } while (keepGoing);

                        NativeMethods.QueryWorkingSetEx(procHndl, workingSetPtr, wsInfoLength.ToInt32());
                        addRange = GenerateWorkingSetExArray(workingSetPtr, wsCurr);
                        //WSInfo.AddRange(addRange);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(String.Format("Exception in processing: {0} {1}", wsInfoLength, ex));
                    }
                    finally { Marshal.FreeHGlobal(workingSetPtr); }

                    foreach (var region in Regions)
                    {
                        var rHash = new MemPageHash();
                        Extract e = null;
                        if (((int)region.AllocationProtect & 0xf0) != 0)
                        {
                            GetModuleFileNameEx(procHndl, new IntPtr(region.AllocationBase), name, 1 << 16);

                            // try to load it from memory
                            try
                            {
                                // see if we have a header
                                NativeMethods.ReadProcessMemory(procHndl, new IntPtr(region.AllocationBase), memBlock, memBlock.Length, readin);
                            }
                            catch (Exception ex) { Console.Write(ex); }

                            e = Extract.IsBlockaPE(memBlock);
                            if (e != null)
                                e.FileName = name.ToString();

                            Byte[] hdrHash = null;

                            if (memBlock != null)
                                hdrHash = ha.ComputeHash(memBlock);

                            // save rHash
                            AllMemState[Id][region.AllocationBase] = new MemState() { e = e, pHash = rHash };

                            rHash.ModuleName = name.ToString();
                            rHash.Id = p.pInfo.ProcessID;
                            rHash.ProcessName = p.pInfo.ProcessName;
                            rHash.AllocationBase = region.AllocationBase;
                            rHash.BaseAddress = region.BaseAddress;
                            rHash.Size = region.RegionSize;
                            rHash.HdrHash = Convert.ToBase64String(hdrHash);
                            if (e != null)
                            {
                                rHash.TimeDateStamp = e.TimeStamp;
                                rHash.ImageSize = (uint)e.SizeOfImage;
                            }

                            // we do not have range info so we have todo this expensive check 
                            // this is really to keep the memory pressure low more than anything
                            if (addRange == null)
                            {
                                for (long addr = region.BaseAddress; addr < region.BaseAddress + region.RegionSize; addr += 4096)
                                {
                                    if (((int)region.AllocationProtect & 0xf) == 0)
                                        continue;

                                    if (!NativeMethods.ReadProcessMemory(procHndl, new IntPtr(addr), memBlock, memBlock.Length, readin))
                                        rHash.HashSet.Add(new PageHashBlock() { Address = addr, Hash = "***BAD_READ***" });
                                    else
                                    {
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
                            }
                            else
                            {
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
                                            rHash.HashSet.Add(new PageHashBlock() { Address = addr.VirtualAddress, Hash = "***BAD_READ***" });
                                        else
                                        {
                                            rHash.HashedBlocks++;
                                            rHash.HashSet.Add(new PageHashBlock() { Address = addr.VirtualAddress, Hash = Convert.ToBase64String(ha.ComputeHash(memBlock)) });
                                        }
                                    }
                                    else
                                    {
                                        TotShare++;
                                        rHash.SharedAway++;
                                    }

                                }
                            }
                            if (rHash.HashSet.Count > 0)
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
    }
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
	$assemblyRange = @("System.dll", $location)
	$compileParams.ReferencedAssemblies.AddRange($assemblyRange)
	$compileParams.GenerateInMemory = $True
	[void]$codeProvider.CompileAssemblyFromSource($compileParams, $code)
	
	Add-Type -TypeDefinition $code -Language CSharp
	foreach ($h in [MemTest.NativeMethods]::GetPageHashes($ProcNameGlob))
	{
		$h | ConvertTo-Json
	}
	
	return
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
	$Module = [System.IO.Path]::GetFileName($itemX.ModuleName)
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
			$Process = [pscustomobject]@{
				Name   = $item.ProcessName
				Id	   = $item.Id
				TotalChecked = $item.TotalChecked
				TotalValidated = $item.TotalValidated
                FullName = $item.ProcessName  + " " + $item.Id
                $ratio = ($item.TotalValidated / $item.TotalChecked)
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
    Out-SquarifiedTreeMap -InputObject $Procs.Children -Width 1024 -Height 768 -DataProperty Size -HeatmapProperty Heat -MaxHeatMapSize 1.0 -LabelProperty Label -Tooltip $Tooltip -ShowLabel {"$($This.LabelProperty)"}
}
