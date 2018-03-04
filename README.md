# PDB2JSON Scripting examples

PDB2JSON is an [Azure Functions](https://github.com/Azure/Azure-Functions) based application

![Verification of memory output](https://raw.githubusercontent.com/K2/Scripting/master/cloud%20forensics.gif)

This server contains the **__largest hash database ever constructed.__**  This hash databse is derived from SHA256 and can securely authenticate the running memory acquired from Windows systems using a variety of open source tools.

This repository contains several scripts that demonstrate the use of the JSON based interface to the network hosted  Code+PDB analysis server.

Only SHA256 hash values are used in this protocol, __no binary data is uploaded__.

Feel free to test the size or extent of our hash database by scanning you're systems. I can make such a **bold statement** since I developed the concept of JIT hashing.  JIT hashing is a just in time methodology that allows for the white listing and integrity protection of running memory across a variety of systems.  As running memory is modified by an OS at load time in an expected way, it is infeasable to pre-compute the nessissary hash values to authenticate these systems.  Pre computing page hash values are a, waste of time (not always), typically for running system integrity verification. https://github.com/K2/HashServer can be used locally in compbination with the public server to host local software into a JIT model to authenticate code files in running memory.

## Server interfaces

https://github.com/K2/Scripting/blob/master/dt.sh demonstrates how to call the majority of functions not covered by the PowerShell and Python scripts.

* typedef
  * Request the JSON formatted RAW data type definition
  * Used to support automatic 'profile' generation for Volatiltiy, Rekall and https://github.com/ShaneK2/inVtero.net 
    * [inVteroCore](https://github.com/ShaneK2/inVtero.net) is a .net core version of [inVtero.net](https://github.com/ShaneK2/inVtero.net) that exposes PowerShell interfaces instead of IronPython it uses pdb2json so there is no need to request the user to know __anything about the memory dump they are analyzing__, this enables __automation__

* SymFromName
  * An API call which returns symbol information based on a name (i.e. _EPROCESS)

* SymFromAddr
  * Returns a symbol that is located at the virtual address specified

* Relocs
  * Return the relocation information associated with a perticular binary file
    * This is what is needed to be combined with dumped code to reconstitute a 'matching' binary.  This means you can recover the exact binary that the OS loaded into memory.

* PageHash
  * This call is used to verify SHA256 values

## Volatility [plugin](https://github.com/K2/Scripting/blob/master/inVteroJitHash.py)



Expanding to other platforms is now super easy.  The minimum protocol format is as follows;

```python
import requests
req_json = {
    "HdrHash":  "QUTB1TPisyVGMq0do/CGeQb5EKwYHt/vvrMHcKNIUR8=",
    "TimeDateStamp":  3474455660,
    "AllocationBase":  140731484733440,
    "BaseAddress":  140731484737536,
    "ImageSize":  1331200,
    "ModuleName":  "ole32.dll",
    "HashSet":[{ "Address":  140731484798976, "Hash":  "+REyeLCxvwPgNJphE6ubeQVhdg4REDAkebQccTRLYL8="},
               { "Address":  140731484803072, "Hash":  "xQJiKrNHRW739lDgjA+/1VN1P3VSRM5Ag6OHPFG6594="},
               { "Address":  140731484807168, "Hash":  "ry9yVHhDQohYTfte0A4iTmNY8gDDfKUmFpxsWF67rtA="},
               { "Address":  140731484811264, "Hash":  "bk31Su+2qFGhZ8PLN+fMLDy2SqPDMElmj0EZA62LX1c="},
               { "Address":  140731484815360, "Hash":  "0RyIKfVFnxkhDSpxgzPYx2azGg59ht4TbVr66IXhVp4="}
              ]
            }
requests.post("https://pdb2json.azurewebsites.net/api/PageHash/x", json=req_json).json()
```

The HdrHash is the only thing that may change or go away, it's very annoying to deal with.  To maintain single page granularity (i.e. we can't nessissiarlly seek over the entire module if it's not paged in) we can be a bit restricted to repair modfiiactions to the header at load time.  The easiest one is the origional base address, the next one down is probably the CLR patch that is made to every CLR binary (the final non-zero bytes in the text section of a CLR are hot patched at load time), however there are quite a few issues with bound imports and the sort that really bloat out the code, and for what?  It's not even +X, I guess there are some pretty effetive attacks that you can do leveraging the PE header with respect to overlapping, invalid sizes/layouts that can make it easier to hide in the address space.  (FWIW I think the Windows loader maxes out at 96 sections per PE despite the 16bit capacity).

That said, if we ignore HdrHash right now, to construct the remainder of this JSON call is a cake walk.  A lot of the testing I've done seems to indicate that this technique dosent have that many drawbacks.  And if it's focused on this one purpose, the benifit of having no database to manageg is helpful. 

## Using the HashServer

You can now validate (custom) software locally.  There is NO database, all the memory integrity validation is just in time, the server uses the relocation information from the client to calculate the SHA256 hash validation per-page and reports on the adjusted value.  This dramatically lowers the TCO / administrative overhead over traditional golden-image type integrity checking.

When combined with a local HashServer. Test-AllVirtualMemory.ps1 will give you a binary hex diff view of memory artifacts and also the capability of validating custom software that is not in the public repository.

Currently you just have to override HashServerUri to point to you're local HashSever to validate results against it and to enable the hex view/diffing.  (right click on a module in the TreeMap to see that).

### GUI

Left click into the TreeView, Right Click a module to get the hex-diff view

The performance difference between coding to the Document interfaces and lower layer TextRendering on WPF is pretty astounding.  It's also impressive that PowerShell can be involved in the render pass from the UI. I left the first implmentation of the DiffView enable feel free to investigate the differences. 

```ps
Add-Type -AssemblyName PresentationFramework 
Get-FastBinDiff c:\temp\mem_ctf.bin C:\windows\system32\msctf.dll
Get-BinDiff c:\temp\mem_ctf.bin C:\windows\system32\msctf.dll
```


![Verification of memory output](https://raw.githubusercontent.com/K2/Scripting/master/BinaryDiffView.jpg)

## Bug/workaround
Right now there is a bug in the PS code, you need to run these lines as a workaround for now;

```ps
Add-Type -AssemblyName PresentationFramework 
Add-Type -AssemblyName PresentationCore
Import-Module ShowUI
```

This will allow the GUI to function properly.

=======

## Server

Current server will adjust it's database to match you're Relocations on demand.  5TB of MS Software Pre-Loaded.  Adding Google, Mozilla & Adobe soon.  

Only hash values of mapped code sections are transmitted in JSON.

* Free/Unlimited access 
* 64bit & wow64 (32 on 64) support/tested

Updates are fast & furious please check back for fixes, new features, golden set's and anything else.

### dt.sh

#### Extract JSON symbol information from network database (allows for analyzing MS binaries from Linux or OSX cake)

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

### Test-AllVirtualMemory.ps1

```powershell
. .\Test-AllVirtualMemory.ps1 -aUserName files -aPassWord qwertyqaz -TargetHost Server16 -GUIOutput -MaxThreads 256 -ElevatePastAdmin
```

This is the output of a the remote memory integrity checking script.  I've hosted a massive 5TB set of Windows SHA256 checksums (currently best supported on 10/Server2016, I'm back porting fixes to help with XP+ and some forms of CLR binaries soon, thoes will work less aesome) however it allows for a remote inspect of all user space binaries and reports as to if they are listed in my hosted DB.  Feel free to validate the results as it's more likyly a MITM or some other sort of exploit on SSL than my DB is p0wned ;)

I may release the server code at some point, but feel free to poke around.  

If you run it in the current script scope you get back $ArrayList that contain's the comprehensive results. Every web request & hashed value, etc.

![Verification of memory output](https://github.com/K2/Scripting/blob/master/Updated-Navigation.JPG?raw=true)
