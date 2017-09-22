# Scripting
PS / Bash / Other scripts For FUN!

# Using the HashServer 

When combined with a local HashServer. Test-AllVirtualMemory.ps1 will give you a binary hex diff view of memory artifacts and also the capability of validating custom software that is not in the public repository.

Currently you just have to override HashServerUri to point to you're local HashSever to validate results against it and to enable the hex view/diffing.  (right click on a module in the TreeMap to see that).


## Bug/workaround
Right now there is a bug in the PS code, you need to run these lines as a workaround for now;

```ps
Add-Type -AssemblyName PresentationFramework 
Add-Type -AssemblyName PresentationCore
Import-Module ShowUI
```

This will allow the GUI to function properly.


## dt.sh 
### Extract JSON symbol information from network database (allows for analyzing MS binaries from Linux or OSX cake)
```bash
/usr/local/bin/dt.sh is called with an input file -i [[FILE_TO_PARSE]] and one of [[-t | -A | -X | -r]]
-i input_PE_FILE (required)
-t _TYPEDUMP (_EPROCESS or _POOL_HEADER or use wildcard matching * just * for everything)
-X Name_*_WildCard
-A 0xADDRESS
-r (returns relocation data)
-h (this help)
-b [[base_va]] (optional)
-f output_file (optional)
detected arguments were; INPUT=[] (file must exist) verbose=[[0]], output_file=[['']]
ADDRESS=[[0]] XSCAN=[[]] RERE=[[]]
typedef=[[]] Leftovers:
```

## Test-AllVirtualMemory.ps1

```powershell
. .\Test-AllVirtualMemory.ps1 -aUserName files -aPassWord qwertyqaz -TargetHost Server16 -GUIOutput
```

This is the output of a the remote memory integrity checking script.  I've hosted a massive 5TB set of Windows SHA256 checksums (currently best supported on 10/Server2016, I'm back porting fixes to help with XP+ and some forms of CLR binaries soon, thoes will work less aesome) however it allows for a remote inspect of all user space binaries and reports as to if they are listed in my hosted DB.  Feel free to validate the results as it's more likyly a MITM or some other sort of exploit on SSL than my DB is p0wned ;)

I may release the server code at some point, but feel free to poke around.  

If you run it in the current script scope you get back $ArrayList that contain's the comprehensive results. Every web request & hashed value, etc.

![Verification of memory output](https://github.com/K2/Scripting/blob/master/Updated-Navigation.JPG?raw=true)
