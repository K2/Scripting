# // Copyright(C) 2017 Shane Macaulay smacaulay@gmail.com
# //
# // This program is free software: you can redistribute it and/or modify
# // it under the terms of the GNU Affero General Public License as
# // published by the Free Software Foundation, either version 3 of the
# // License, or(at your option) any later version.
# //
# //This program is distributed in the hope that it will be useful,
# // but WITHOUT ANY WARRANTY; without even the implied warranty of
# // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# // GNU Affero General Public License for more details.
# //
# // You should have received a copy of the GNU Affero General Public License
# // along with this program.If not, see<http://www.gnu.org/licenses/>.

###############################################################################################
#
# To use this with volatility place this .py anywhere, ensure you have volatility working.
# For example the command line below will simply run the invterojithash against the input memory image
#
# python vol.py --plugins=[path-to-folder-where-this-code-is] -f "c:\temp\10 ENT 1607-Snapshot1.vmem"
#  --profile=Win10x64_14393 invterojithash
#
# I'll be looking to make updates feel free to give me some issues through "github.com/K2"
#
# 
# OPERATIONS: The client script you run perform's a basic sha256 of whatever is in memory with no regard
# for relocations or anything.  Very simple.  All of the heavy lifting magic is done on the server time 
# on demand integrity hashes are computed based on you're client's described virtual address.
# i.e. You say kernel32 is loaded at address X.  The server responds and adjusts it's hash database in real time
# so there is very little work on the client side.
#
# I haven't written the PE header fixes yet for this code as it's currently done for the PowerShell, in effect
# there are so many changes for the PE header, it's like a shotgun blast of bits that need adjusting. 
#
# Enjoy!
################################################################################################

import volatility.commands as commands
import volatility.utils as utils
import volatility.win32.tasks as tasks
import time
import base64
import sys
import requests
from Crypto.Hash import SHA256

class inVteroJitHash(commands.Command):
    """Use the public free inVtero JIT Page hash server to respond with integrity information"""
    #"http://Zammey:3342/api/PageHash/x"
    JITHashServer = "https://pdb2json.azurewebsites.net/api/PageHash/x"
    StatsOutput = True
    StartTime = time.time()
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args)
        
    def is_nxd(self, vaddr, addr_space):
        '''
        I want too know if the page table defines
        this virtualaddress to be restricted from execution.
        True means that is something we can ignore based on NX or missing or not valid.

        The JitPageHash service endpoint is running with the json2pdb job. 
        "https://pdb2json.azurewebsites.net/api/PageHash/x"

        A sample "python.requests" request/response that demonstrates the expected functionality.

        The response information is very terse so it's a good idea to maintain some meta-information
        across the request since it's pumped into the data render_text method
        ---- snip -- snip ---- below here is copy/pasteable into python shell to test ---- snip -- snip ----
import requests
req_json = {
    "HdrHash":  "QUTB1TPisyVGMq0do/CGeQb5EKwYHt/vvrMHcKNIUR8=",
    "TimeDateStamp":  3474455660,
    "AllocationBase":  140731484733440,
    "BaseAddress":  140731484737536,
    "ImageSize":  1331200,
    "ModuleName":  "ole32.dll",
    "HashSet":[
                    {
                        "Address":  140731484798976,
                        "Hash":  "+REyeLCxvwPgNJphE6ubeQVhdg4REDAkebQccTRLYL8="
                    },
                    {
                        "Address":  140731484803072,
                        "Hash":  "xQJiKrNHRW739lDgjA+/1VN1P3VSRM5Ag6OHPFG6594="
                    },
                    {
                        "Address":  140731484807168,
                        "Hash":  "ry9yVHhDQohYTfte0A4iTmNY8gDDfKUmFpxsWF67rtA="
                    },
                    {
                        "Address":  140731484811264,
                        "Hash":  "bk31Su+2qFGhZ8PLN+fMLDy2SqPDMElmj0EZA62LX1c="
                    },
                    {
                        "Address":  140731484815360,
                        "Hash":  "0RyIKfVFnxkhDSpxgzPYx2azGg59ht4TbVr66IXhVp4="
                    }
                ]
}
requests.post("https://pdb2json.azurewebsites.net/api/PageHash/x", json=req_json).json()

---- snip -- snip ---- the lines below are the output of the above service call ---- snip -- snip  ----

[{u'Address': 140731484733440L, u'HashCheckEquivalant': True},
 {u'Address': 140731484798976L, u'HashCheckEquivalant': True},
 {u'Address': 140731484803072L, u'HashCheckEquivalant': True},
 {u'Address': 140731484807168L, u'HashCheckEquivalant': True},
 {u'Address': 140731484811264L, u'HashCheckEquivalant': True},
 {u'Address': 140731484815360L, u'HashCheckEquivalant': True}]
        '''

        vaddr = long(vaddr)
        retVal = True
        pml4e = addr_space.get_pml4e(vaddr)
        if not addr_space.entry_present(pml4e):
            return True
        pdpe = addr_space.get_pdpi(vaddr, pml4e)
        if not addr_space.entry_present(pdpe):
            return True
        if addr_space.page_size_flag(pdpe):
            return addr_space.is_nx(pdpe)
        pgd = addr_space.get_pgd(vaddr, pdpe)
        if addr_space.entry_present(pgd):
            if addr_space.page_size_flag(pgd):
                return addr_space.is_nx(pgd)
            else:
                pte = addr_space.get_pte(vaddr, pgd)
                return addr_space.is_nx(pte)
        return True

    def mod_get_ptes(self, mod, addr_space):
        for vpage in range(mod.DllBase, mod.DllBase + mod.SizeOfImage, 4096):
            yield vpage, self.is_nxd(vpage, addr_space)

    def HashPage(self, data):
        sha = SHA256.new()
        if data is None:
            return "NULL INPUT"
        sha.update(data)
        return base64.b64encode(sha.digest())

    def calculate(self):
        StartTime = time.time()
        addr_space = utils.load_as(self._config)
        tasklist = []
        modslist = []
        tasklist = [t for t in tasks.pslist(addr_space)]
        taski = 0
        for task in tasklist:
            taski += 1
            print("\nScanning: " + task.ImageFileName + "(" + str(taski) + " of " + str(tasklist.__len__()) + ")\n")
            proc_as = task.get_process_address_space()
            for mod in task.get_load_modules():
                hashAddr = []
                hashVal = []
                for vpage, nx in self.mod_get_ptes(mod, proc_as):
                    data = proc_as.read(vpage, 4096)
                    if data is None:
                        continue
                    if(nx):
                        continue
                    hashAddr.append(str(vpage))
                    hashVal.append(self.HashPage(data))

                req_hdr = { 
                    "ModuleName": str(mod.FullDllName or ''),
                    "ImageSize": str(mod.SizeOfImage),
                    "BaseAddress": str(mod.DllBase),
                    "AllocationBase": str(mod.DllBase),
                    "TimeDateStamp": str(int(mod.TimeDateStamp)),
                    "HdrHash": self.HashPage(proc_as.read(mod.DllBase, 4096)),
                    "HashSet": [{"Address": a, "Hash": h} for a, h in zip(hashAddr, hashVal)]
                }
                r = requests.post(self.JITHashServer, json=req_hdr)
                yield r

    def render_text(self, outfd, data):
        VirtualBlocksChecked = 0
        VBValidated = 0
        ScannedMods = 0
        outfd.write("pdb2json JIT PageHash calls under way...  (endpoint is " + self.JITHashServer + ")")
        for r in data:
            failed = False
            #Isolate some context from the request so the output makes a little sense
            idx = r.request.body.find("ModuleName")+13
            idx_end = r.request.body[idx:].find(",")
            info = r.request.body[idx:idx+idx_end]
            ScannedMods += 1
            ModBlksValidated = 0
            #outfd.write("Request info for module " + info + " ")
            if r.text is not None:
                try:
                    # The header is a known set of fixes let's only count +x code anyhow since the PE header is not mappex +x typically anyhow
                    modPageCount = r.json().__len__() - 1
                    if modPageCount == 0:
                        modPageCount = 1 
                    VirtualBlocksChecked += modPageCount
                    responses=r.json()
                    for x in responses:
                        # Super verbose output
                        if self.StatsOutput is False:
                            print (str(hex(x["Address"])) + " was verified SHA256? " + str(x["HashCheckEquivalant"]))
                        # if we fail the hash check do not accumulate the results
                        if x["HashCheckEquivalant"] is not True:
                            continue
                        ModBlksValidated += 1
                        VBValidated += 1
                    outfd.write("{0:<60} {1:>10}% \t{2:x} bytes\n".format(info, str((ModBlksValidated * 100.0 / modPageCount)), modPageCount*0x1000))
                except:
                    #some binaries are not in the database. This is MS software and pretty much the OS's
                    failed = True
                    outfd.write("Exception (" + str(sys.exc_info()[0]) + ")")
            else:
                failed = True
                outfd.write("Non-exception failure, ")
            if failed is True:
                outfd.write(") failure was handling input: " + info + "\n")

        if self.StatsOutput:
            print ("Run Time: " + str(time.time() - self.StartTime))
            print ("A total of " + str(ScannedMods) + " modules scanned.  Scanned Pages " + str(VirtualBlocksChecked) + " with " + str(VBValidated) + " Validations.")
            print (str(VBValidated * 100.0 / VirtualBlocksChecked) +  " percent of queried code was able to be 100% identified as a known code file. Validated bytes: " + str(VBValidated * 0x1000) + " of a requested: " + str(VirtualBlocksChecked * 0x1000))