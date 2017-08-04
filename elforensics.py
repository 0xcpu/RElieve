#!/usr/bin/env python3

import lief
import sys
import termcolor as tc
from capstone import *


def get_elf_class_str(identity_class):
    if   identity_class == lief.ELF.ELF_CLASS.CLASS32:
        return "32"
    elif identity_class == lief.ELF.ELF_CLASS.CLASS64:
        return "64"
    else:
        print("ELF_CLASS is NONE, aborting disassembling...")
        return None


def get_capstone_arch(machine_type, mode):
    if   machine_type == lief.ELF.ARCH.ARM:
        if mode == "32":
            return CS_ARCH_ARM
        else:
            return CS_ARCH_ARM64
    elif machine_type == lief.ELF.ARCH.MIPS:
        return CS_ARCH_MIPS
    elif machine_type == lief.ELF.ARCH.PPC:
        return CS_ARCH_PPC
    elif machine_type == lief.ELF.ARCH.i386:
        return CS_ARCH_x86
    elif machine_type == lief.ELF.ARCH.x86_64:
        return CS_ARCH_X86
    else:
        print("Unsupported architecture, aborting disassembling...")
        return None


def get_capstone_mode(arch, mode):
    if   (arch == CS_ARCH_ARM) or (arch == CS_ARCH_ARM64):
        return CS_MODE_ARM
    elif arch == CS_ARCH_MIPS:
        if mode == "32":
            return CS_MODE_MIPS32
        else:
            return CS_MODE_MIPS64
    elif arch == CS_ARCH_PPC:
        if mode == "32":
            return CS_MODE_32
        else:
            return CS_MODE_64
    elif arch == CS_ARCH_X86:
        if mode == "32":
            return CS_MODE_32
        else:
            return CS_MODE_64
    else:
        raise "Unsupported capstone arch"


def check_entrypoint(binary):
    entrypoint = binary.header.entrypoint
    section = binary.section_from_virtual_address(entrypoint)
    print(tc.colored("Entrypoint at virtual address: {}".format(hex(entrypoint)), "green"))
    print("{0} {1} {2}".format(tc.colored("Section:","green"),
                               tc.colored(section.name, "red"),
                               tc.colored("contains the entrypoint", "green")))

    mode = get_elf_class_str(binary.header.identity_class)
    if mode == None:
        return
    arch = get_capstone_arch(binary.header.machine_type, mode)
    if arch == None:
        return
    dis_mode = get_capstone_mode(arch, mode)

    code = bytes(binary.get_content_from_virtual_address(entrypoint, 0x30))
    md = Cs(arch, dis_mode)
    for i in md.disasm(code, entrypoint):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


    print()

        
def check_rwx_sections(binary):
    print(tc.colored("Segments with PF_W + PF_X or PF_R + PF_W + PF_X flags", "green"))

    # check segments that have PF_W + PF_X or PF_R + PF_W + PF_X
    for seg in binary.segments:
        if (seg.flags == 0x3) or (seg.flags == 0x7):
            print("{0} {1}".format(tc.colored("Segment:", "cyan"),
                                   tc.colored(str(seg.type).split('.')[1], "red")))

    print()


def check_ctors_array(binary):
    print(tc.colored("Check if .ctors/.fini_array function pointers "
                     "were (possibly) patched", "green"))

    elf_class = get_elf_class_str(binary.header.identity_class)
    if elf_class == "64":
        reg_size = 8
    else:
        reg_size = 4

    for sect in binary.sections:
        if (sect.name == ".ctors") or (sect.name == ".init_array"):
            content = sect.content

            for i in range(0, sect.size, reg_size):
                addr = int.from_bytes(content[i : i + reg_size], byteorder="little")
                print("{0} {1}".format(tc.colored("Check address: ", "cyan"),
                                       tc.colored(hex(addr), "yellow")))

                text_sect = binary.get_section(".text")
                is_lesser  = addr < text_sect.virtual_address
                is_greater = addr > text_sect.virtual_address + text_sect.size
                if is_lesser or is_greater:
                    print("{0} {1}".format(tc.colored(hex(addr), "yellow"),
                                           tc.colored("is outside of .text section", "red")))
                
                
    print()

                    
def analyse():
    if len(sys.argv) < 2:
        print("[USAGE]: {0} <executable>".format(sys.argv[0]))
        sys.exit(1)

    try:
        binary = lief.ELF.parse(sys.argv[1])
    except lief.bad_file as err:
        print("Error: {0}".format(err))
        sys.exit(1)

    check_entrypoint(binary)
    check_rwx_sections(binary)
    check_ctors_array(binary)


if __name__ == "__main__":
    analyse()
