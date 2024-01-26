"""

This script unpacks UPX packed binaries using Qiling Framework.
It hooks the VirtualProtect function right before the OEP is called.
The VirtualProtect function is used to make the memory page executable before calling each TLS callback.
The OEP is found right below the sub rsp/esp , -0x80 instruction which is used to cleanup the stack.

"""
import sys
from os import name
from qiling import Qiling
from qiling.loader.pe import QlLoaderPE
from capstone import Cs
from qiling.const import *
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from pefile import PE
import ntpath
import argparse
import lief
import logging


# Define the PE architecture

class Arch:
    ARCH_X86 = 0
    ARCH_X64 = 1

# In order to unpack UPX we need to find the exact moment the binary is unpacked in memory.
# We can do this by hooking the VirtualProtect since it is used to change the memory protection of a memory page on
# the unpacked executable right before jumping to the OEP.
# VirtualProcect is used to make the memory page executable before calling each TLS callback.


class Unpacker():
    hooked = False
    next_jmp = False
    oep = 0
    base_address = 0

    def __init__(self):
        self.bin = None
        self.pe = None
        self.arch = None
        self.ql: Qiling = None
        self.output = None

    def run(self, input, output=None):
        self.bin = input
        self.pe = PE(input)
        self.arch = Arch.ARCH_X86 if self.pe.FILE_HEADER.Machine == 0x14c else Arch.ARCH_X64
        self.ql: Qiling = None
        self.output = ntpath.basename(
            input)+".unpacked" if output is None else output

        logging.info(f"Unpacking {self.bin} to {self.output}")
        # first copy the binary to the correct rootfs
        rootfs = "rootfs/x86_windows" if self.arch == Arch.ARCH_X86 else "rootfs/x8664_windows"
        with open(f"{rootfs}/bin/{ntpath.basename(self.bin)}", "wb") as f:
            f.write(open(self.bin, "rb").read())

        self.unpack(f"{rootfs}/bin/{ntpath.basename(self.bin)}", rootfs)

    def unpack_binary(self, ql: Qiling, addr):
        # dump unpacked binary from memory
        # find out where packed.exe is mapped in memory and dump it
        # loop memory pages
        loader: QlLoaderPE = ql.loader
        membin = PE(data=ql.mem.read(addr, 0x1000))
        # dump the binary (DosHeader + PEHeader + SectionHeaders + Sections)
        with open(self.output, "wb") as f:
            f.write(ql.mem.read(addr, membin.OPTIONAL_HEADER.SizeOfHeaders))

        # dump sections add padding if needed
        bin = lief.parse(self.output)

        # TODO: lazy dumping
        # dump sections by matching the VirtualAddress with the RawAddress
        # this way we don't need to align the whole binary
        # !!! this is ugly and actually make the final binary bigger !!!
        # the correct way would be rewriting the PE header section by section removing the relocations, and by fixing the IAT
        # sadly due to time constraints I'll stick with this ugly solution
        for i in range(membin.FILE_HEADER.NumberOfSections):
            logging.debug(f"Dumping section {membin.sections[i].Name}")
            section = membin.sections[i]
            section_data = ql.mem.read(addr + section.VirtualAddress,
                                       section.Misc_VirtualSize)
            bin.sections[i].content = section_data
            bin.sections[i].offset = section.VirtualAddress
            bin.sections[i].size = section.Misc_VirtualSize
            bin.sections[i].sizeof_raw_data = section.Misc_VirtualSize
            bin.sections[i].pointerto_raw_data = section.VirtualAddress

        # lief can rewrite the binary for us and also take care of the padding between sections
        bin.write(self.output)

        logging.debug(
            f"Unpacked binary dumped to {self.output} with OEP: {hex(self.oep)}")
        ql.emu_stop()

    def instr_hook(self, ql: Qiling, addr, size, cs: Cs):
        for instr in cs.disasm(ql.mem.read(addr, size), addr):
            if not self.next_jmp:
                # check if we are executing sub rsp, -0x80
                if instr.mnemonic == "sub":
                    # check if we are subtracting from rsp/esp
                    if self.arch == Arch.ARCH_X64:
                        if instr.op_str == "rsp, -0x80":
                            self.next_jmp = True
                    else:
                        if instr.op_str == "esp, -0x80":
                            self.next_jmp = True
            else:
                if instr.mnemonic == "jmp":
                    # check if we are jumping to absolute address
                    if instr.op_str.startswith("0x"):
                        self.oep = int(instr.op_str, 16)
                        self.next_jmp = False
                        # remove hook
                        ql.hook_code(
                            self.instr_hook, ql.arch.disassembler, begin=0, end=0)
                        # unpack binary
                        self.unpack_binary(ql, self.base_address)

    def unpack(self, bin, rootfs):
        logging.info("Mapping binary")
        self.ql = Qiling([bin], rootfs, verbose=QL_VERBOSE.OFF)
        self.ql.os.set_api(
            "VirtualProtect", my_virtualprotect, QL_INTERCEPT.CALL)
        logging.info("Starting emulation")
        self.ql.run()


# This hook is responsible for finding the base address of the unpacked binary.
# also we setup the instr_hook here so we can speed up a bit the emulation.
@winsdkapi(cc=STDCALL, params={
    "lpAddress": POINTER,
    "dwSize": DWORD,
    "flNewProtect": DWORD,
    "lpflOldProtect": POINTER}
)
def my_virtualprotect(ql: Qiling, address, params):
    if not QUnpack.hooked:
        ql.hook_code(QUnpack.instr_hook, ql.arch.disassembler)
        QUnpack.base_address = params["lpAddress"]
        QUnpack.hooked = True
    return 0x1


QUnpack = Unpacker()

# Example usage:
# strings examples/packed.exe | grep "Hello"
# <nothing>
# python unpack.py -i examples/packed.exe
# strings packed.exe.unpacked  | grep "Hello"
# Hello World!
#
# With the unpacked binary we can see that the string "Hello World!" is present.
# also the OEP is fully extracted thus we can still statically analyze the unpacked binary.
# to make it run we need to fix the IAT.

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="input file", required=True)
    parser.add_argument("-o", "--output", help="output directory")

    args = parser.parse_args()

    try:
        if args.input:
            if args.output:
                QUnpack.run(args.input, args.output)
            else:
                QUnpack.run(args.input)
    except Exception as e:
        logging.error(f"Unpacking failed: {e}")
