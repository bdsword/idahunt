#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Filter for arbitrary names to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/names.py -n Download -e exe -a 32"

# By BDSword.
# Please:
# $ pip install python-magic-bin
# Before run the idahunt

import argparse
import os
import re
import sys
import subprocess
import time
import magic


PE32_List = [
    "PE32 executable (console) Intel 80386, for MS Windows",
    "PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32 executable (DLL) (console) Intel 80386, for MS Windows",
    "PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows",
    "PE32 executable (DLL) (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows",
    "PE32 executable (DLL) (GUI) Intel 80386 (stripped to external PDB), for MS Windows",
    "PE32 executable (DLL) (native) Intel 80386, for MS Windows",
    "PE32 executable (GUI) Intel 80386, for MS Windows",
    "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32 executable (native) Intel 80386, for MS Windows",
    "PE32 executable (Unknown subsystem 0x10) Intel 80386, for MS Windows",
    "8086 relocatable (Microsoft)"
]

PE64_List = [
    "PE32+ executable (console) x86-64, for MS Windows",
    "PE32+ executable (console) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (DLL) (console) x86-64, for MS Windows",
    "PE32+ executable (DLL) (console) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (DLL) (EFI application) x86-64, for MS Windows",
    "PE32+ executable (DLL) (GUI) x86-64, for MS Windows",
    "PE32+ executable (DLL) (GUI) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (DLL) (native) x86-64, for MS Windows",
    "PE32+ executable (GUI) x86-64, for MS Windows",
    "PE32+ executable (GUI) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (native) x86-64, for MS Windows",
    "PE32+ executable (Unknown subsystem 0x10) x86-64, for MS Windows"
]


ELF32_List = [
    "ELF 32-bit LSB executable",
    "ELF 32-bit LSB relocatable",
    "ELF 32-bit LSB shared object"
]

ELF64_List = [
    "ELF 64-bit LSB relocatable",
    "ELF 64-bit"
]

class MagicFile:
    def __init__(self, name):
        self.magic_info = magic.from_file(name)

    def is_pe32(self):
        for info in PE32_List:
            if self.magic_info.startswith(info):
                return True
        return False

    def is_elf32(self):
        for info in ELF32_List:
            if self.magic_info.startswith(info):
                return True
        return False

    def is_pe64(self):
        for info in PE64_List:
            if self.magic_info.startswith(info):
                return True
        return False

    def is_elf64(self):
        for info in ELF64_List:
            if self.magic_info.startswith(info):
                return True
        return False
    
    def is_upx(self):
        return 'UPX compressed' in self.magic_info


def logmsg(s, end=None, debug=True):
    if not debug:
        return
    if type(s) == str:
        if end != None:
            print("[Debug] " + s),
        else:
            print("[Debug] " + s)
    else:
        print(s)


# do we actually treat it?
def filter(f, name, extension, verbose=True):
    if name and not name in os.path.basename(f):
        logmsg("Skipping non-matching name %s in %s" % (name, os.path.basename(f)))
        return None
    filename, file_extension = os.path.splitext(f)
    if extension and not extension.startswith("."):
        extension = "." + extension
    if extension and file_extension != extension:
        logmsg("Skipping non-matching extension %s in %s" % (extension, os.path.basename(f)))
        return None
    if name and not name in os.path.basename(f):
        logmsg("Skipping non-matching name %s in %s" % (name, os.path.basename(f)))
        return None

    magic_file = MagicFile(f)
    if magic_file.is_upx():
        logmsg("{} is upx protected file.".format(f))
        return None
    elif magic_file.is_pe32() or magic_file.is_elf32():
        arch_ = 32
    elif magic_file.is_pe64() or magic_file.is_elf64():
        arch_ = 64
    else:
        logmsg("{} is neither 32 or 64 arch pe file.".format(f))
        return None

    ida_db_ext = ['.idb', '.i64']
    analyzed = False
    for ext in ida_db_ext:
        if os.path.isfile(os.path.join(os.path.splitext(f)[0], ext)):
           analyzed = True
           break
    if analyzed:
        logmsg("{} is analyzed.".format(f))
        return None
        
    return f, arch_

def main(f, cmdline):
    # We override sys.argv so argparse can parse our arguments :)
    sys.argv = cmdline.split()

    parser = argparse.ArgumentParser(prog=cmdline)
    parser.add_argument('-n', dest='name', default=None, help='pattern \
                        to include in the name')
    parser.add_argument('-e', dest='extension', default=None, help='Exact \
                        extension to match')
    parser.add_argument('-v', dest='verbose', default=False, action='store_true'
                        , help='be more verbose to debug script')
    args = parser.parse_args()

    return filter(f, args.name, args.extension, args.verbose)

