#!/usr/bin/env python3

import lief
import sys
import termcolor as tc
import tempfile
import subprocess
import json
from capstone import *


is_lesser  = lambda addr, sect: addr < sect.virtual_address
is_greater = lambda addr, sect: addr > sect.virtual_address + sect.size


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
        return CS_ARCH_X86
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


def disas(binary, addr, length):
    print(tc.colored("<Capstone disassembly>", "green"))

    mode = get_elf_class_str(binary.header.identity_class)
    if mode == None:
        return
    arch = get_capstone_arch(binary.header.machine_type, mode)
    if arch == None:
        return
    dis_mode = get_capstone_mode(arch, mode)

    try:
        code = bytes(binary.get_content_from_virtual_address(addr, length))
    except lief.not_found as err:
        print(err)
        return

    asm_code = ""
    md = Cs(arch, dis_mode)
    for i in md.disasm(code, addr):
        asm_code += "0x{0}:\t{1}\t{2}\n".format(i.address, i.mnemonic, i.op_str)

    return asm_code


def check_entrypoint(binary):
    entrypoint = binary.header.entrypoint
    section = binary.section_from_virtual_address(entrypoint)
    print(tc.colored("Entrypoint at virtual address: {}".format(hex(entrypoint)), "green"))
    print("{0} {1} {2}".format(tc.colored("Section:","green"),
                               tc.colored(section.name, "red"),
                               tc.colored("contains the entrypoint", "green")))

    if is_lesser(entrypoint, section) or is_greater(entrypoint, section):
        print(tc.colored("Suspicious", "red"))
    else:
        print(tc.colored("OK", "cyan"))

    print(disas(binary, entrypoint, 0x30))

    print("Done\n")


def check_rwx_sections(binary):
    print(tc.colored("Segments with PF_W + PF_X or PF_R + PF_W + PF_X flags", "green"))

    # check segments that have PF_W + PF_X or PF_R + PF_W + PF_X
    for seg in binary.segments:
        if (seg.flag == 0x3) or (seg.flag == 0x7):
            print("{0} {1}".format(tc.colored("Segment:", "cyan"),
                                   tc.colored(str(seg.type).split('.')[1], "red")))

    print("Done\n")


def get_register_size(binary):
    elf_class = get_elf_class_str(binary.header.identity_class)
    if elf_class == "64":
        return 8
    else:
        return 4


def check_ctors_array(binary):
    print(tc.colored("Check if .ctors/.fini_array function pointers "
                     "were (possibly) patched", "green"))

    reg_size = get_register_size(binary)

    if   binary.has_section(".ctors"):
        sect = binary.get_section(".ctors")
    elif binary.has_section(".init_array"):
        sect = binary.get_section(".init_array")
    else:
        raise lief.not_found

    content = sect.content

    for i in range(0, sect.size, reg_size):
        addr = int.from_bytes(content[i : i + reg_size], byteorder="little")
        if (hex(addr) == ("0x" + "ff" * reg_size)) or (hex(addr) == "0x0"):
            continue
        print("{0} {1}".format(tc.colored("Checking address: ", "cyan"),
                               tc.colored(hex(addr), "yellow")), end=' ')

        text_sect = binary.get_section(".text")
        if is_lesser(addr, text_sect) or is_greater(addr, text_sect):
            print("{0}".format(tc.colored("is outside of .text section", "red")))
        else:
            print("{0}".format(tc.colored("OK", "cyan")))

    print("Done\n")


def check_got_and_plt(binary):
    print(tc.colored("Check if GOT entries were patched", "green"))

    reg_size = get_register_size(binary)
    # Analyse only executables and shared libraries
    if binary.has_section(".plt"):
        plt = binary.get_section(".plt")
        print("{0} {1} {2}".format(tc.colored(".plt at", "green"),
                                   tc.colored(hex(plt.virtual_address), "yellow"),
                                   tc.colored(hex(plt.virtual_address + plt.size), "yellow")))
    else:
        raise lief.not_found
    if binary.has_section(".got.plt"):
        got_plt = binary.get_section(".got.plt")
    else:
        raise lief.not_found

    content = got_plt.content

    # ignore first 3 entries in GOT, because they are reserved
    for i in range(3 * reg_size, got_plt.size, reg_size):
        addr = int.from_bytes(content[i : i + reg_size], byteorder="little")
        print("{0} {1}".format(tc.colored("Checking address: ", "cyan"),
                               tc.colored(hex(addr), "yellow")), end=' ')

        if is_lesser(addr, plt) or is_greater(addr, plt):
            print("{0}".format(tc.colored("is outside of .plt section", "red")))
            for r in binary.pltgot_relocations:
                if (r.address == (got_plt.virtual_address + i)) and r.has_symbol:
                    print("{0} {1} {2}".format(tc.colored(hex(addr), "yellow"),
                                               tc.colored("should point to", "green"),
                                               tc.colored(r.symbol, "yellow")))
                    break

            print(disas(binary, addr, 0x30))
        else:
            print("{0}".format(tc.colored("OK", "cyan")))

    print("Done\n")


# TO DO: pattern match trampolines instead of outputing all prologues
def check_funcs_trampoline(binary, path):
    print(tc.colored("Check if function(s) prologue contain a trampoline", "green"))

    python2_code = \
                   """
import angr
import json

proj  = angr.Project("{0}", auto_load_libs=False)
cfg   = proj.analyses.CFG()
funcs = dict()

for k, v in dict(proj.kb.functions).iteritems():
    funcs[v.name] = v.addr

print json.dumps(funcs)
                   """.format(path)

    temp_file = tempfile.NamedTemporaryFile(mode='w+', suffix=".py")
    with open(temp_file.name, "w+") as f:
        f.write(python2_code)
    temp_file.file.close()

    python2_proc  = subprocess.Popen(["python2", temp_file.name], stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    output, error = python2_proc.communicate()

    if "ImportError" in error.decode("utf-8"):
        print("{0}\n{1}\n".format(tc.colored("To recover CFG you must have Angr module for Python 2", "white"),
                                  tc.colored("Install with: pip install angr", "magenta")))

        return

    funcs = json.loads(output.decode("utf-8"))
    for fname in binary.imported_functions:
        if fname in funcs:
            del funcs[fname]

    for fname, faddr in funcs.items():
        print("{0} @ {1}".format(tc.colored(fname, "cyan"), tc.colored(hex(faddr), "yellow")))

        prologue  = disas(binary, faddr, 0xA)
        mnemonics = ["jmp", "ret", "retf", "retn", "call", "fld", "fistp", "movd"]
        if (prologue is not None) and any(mnemonic in prologue for mnemonic in mnemonics):
            print(prologue)
        else:
            print("{0}".format(tc.colored("OK", "cyan")))

    print("Done\n")


def check_dynamic_entries(binary):
    print(tc.colored("Check dynamic entries injection", "green"))

    # Normally NEEDED dynamic entries are consecutive, check for entries that aren't consecutive
    last_needed_entry = None
    for i, d in enumerate(binary.dynamic_entries, start=1):
        if d.tag == lief.ELF.DYNAMIC_TAGS.NEEDED:
            if last_needed_entry == None:
                last_needed_entry = i
            else:
                if (i - last_needed_entry) > 1:
                    print("{0} {1} {2}".format(tc.colored("Suspicious NEEDED entry, index", "green"),
                                               tc.colored(str(i), "red"),
                                               tc.colored(d.name, "red")))
                else:
                    last_needed_entry = i

    print("Done\n")


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
    check_got_and_plt(binary)
    check_funcs_trampoline(binary, sys.argv[1])
    check_dynamic_entries(binary)

if __name__ == "__main__":
    analyse()
