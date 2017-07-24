#!/usr/bin/env python3

import lief
import sys
import termcolor as tc


def get_typeval_as_str(lief_type):
    return str(lief_type).split('.')[1]


def show_name(binary):
    print(tc.colored("[::] Name", "blue"))
    print(binary.name)


def enum_header(header):
    def get_ident_props():
        identity  = "\n{0:18} {1}".format("\t\tClass:",   get_typeval_as_str(header.identity_class))
        identity += "\n{0:18} {1}".format("\t\tData:",    get_typeval_as_str(header.identity_data))
        identity += "\n{0:18} {1}".format("\t\tOS ABI:",  get_typeval_as_str(header.identity_os_abi))
        identity += "\n{0:18} {1}".format("\t\tVersion:", get_typeval_as_str(header.identity_version))
        identity += "\n{0:18} {1}".format("\t\tMachine:", get_typeval_as_str(header.machine_type))

        return identity


    print(tc.colored("[::] Header", "blue"))
    print(tc.colored("{0:25} {1}".format("\tEntrypoint:",             hex(header.entrypoint)),                         "green"))
    print(tc.colored("{0:25} {1}".format("\tFile type:",              get_typeval_as_str(header.file_type)),           "green"))
    print(tc.colored("{0:25} {1}".format("\tHeader size:",            hex(header.header_size)),                        "green"))
    print(tc.colored("{0:25} {1}".format("\tIdentity:",               get_ident_props()),                              "cyan"))
    print(tc.colored("{0:25} {1}".format("\tNumber of sections:",     header.numberof_sections),                       "green"))
    print(tc.colored("{0:25} {1}".format("\tNumber of segments:",     header.numberof_segments),                       "green"))
    print(tc.colored("{0:25} {1}".format("\tObject file version:",    get_typeval_as_str(header.object_file_version)), "green"))
    print(tc.colored("{0:25} {1}".format("\tProcessor flag:",         header.processor_flag),                          "green"))
    print(tc.colored("{0:25} {1}".format("\tProgram header offset:",  hex(header.program_header_offset)),              "green"))
    print(tc.colored("{0:25} {1}".format("\tProgram header size:",    hex(header.program_header_size)),                "green"))
    print(tc.colored("{0:25} {1}".format("\tSection header offset:",  hex(header.section_header_offset)),              "green"))
    print(tc.colored("{0:25} {1}".format("\tSection name table idx:", hex(header.section_name_table_idx)),             "green"))
    print(tc.colored("{0:25} {1}".format("\tSection header size:",    hex(header.sizeof_section_header)),              "green"))
    

def show_interpreter(binary):
    print(tc.colored("[::] Interpreter/loader", "blue"))
    if binary.has_interpreter:
        print(binary.interpreter)
    else:
        print(tc.colored("No interpreter/loader", "yellow"))


def show_notes(binary):
    print(tc.colored("[::] Notes section", "blue"))
    if binary.has_notes:
        for n in binary.notes:
            print(n)
    else:
        print(tc.colored("No notes section", "yellow"))


def enum_dyn_entries(binary):
    print(tc.colored("[::] Dynamic entries", "blue"))
    for e in binary.dynamic_entries:
        print(e)


def enum_dyn_relocs(binary):
    print(tc.colored("[::] Dynamic relocations", "blue"))
    for r in binary.dynamic_relocations:
        print(r)


def enum_exp_funcs(binary):
    print(tc.colored("[::] Exported functions", "blue"))
    for f in binary.exported_functions:
        print(f)


def enum_exp_symbols(binary):
    print(tc.colored("[::] Exported symbols", "blue"))
    for s in binary.exported_symbols:
        print(s)


def enum_imp_functions(binary):
    print(tc.colored("[::] Imported functions", "blue"))
    for f in binary.imported_functions:
        print(f)


def enum_imp_symbols(binary):
    print(tc.colored("[::] Imported symbols", "blue"))
    for s in binary.imported_symbols:
        print(s)


def enum_libraries(binary):
    print(tc.colored("[::] Libraries", "blue"))
    for l in binary.libraries:
        print(l)


def enum_sections(binary):
    print(tc.colored("[::] Sections", "blue"))
    for s in binary.sections:
        print(s)
        # Properties
        print(tc.colored("\t{0:15} {1}".format("Alignment",     hex(s.alignment)),           "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Entropy",       s.entropy),                  "cyan"))
        print(tc.colored("\t{0:15} {1}".format("File offset",   hex(s.file_offset)),         "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Flags",         s.flags),                    "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Information",   s.information),              "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Link",          s.link),                     "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Name index",    s.name_idx),                 "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Offset",        hex(s.offset)),              "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Original size", s.original_size),            "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Size",          s.size),                     "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Type",          get_typeval_as_str(s.type)), "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Virtual addr",  hex(s.virtual_address)),     "cyan"))


def enum_segments(binary):
    print(tc.colored("[::] Segments", "blue"))
    for s in binary.segments:
        print(s)
        # Properties
        print(tc.colored("\t{0:15} {1}".format("Alignment",     hex(s.alignment)),           "cyan"))
        print(tc.colored("\t{0:15} {1}".format("File offset",   hex(s.file_offset)),         "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Flags",         s.flag),                     "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Type",          get_typeval_as_str(s.type)), "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Virtual addr",  hex(s.virtual_address)),     "cyan"))
        print(tc.colored("\t{0:15} {1}".format("Virtual size",  hex(s.virtual_size)),        "cyan"))

def run():
    if len(sys.argv) < 2:
        print("[USAGE]: {0} <executable>".format(sys.argv[0]))
        sys.exit(1)

    try:
        binary = lief.ELF.parse(sys.argv[1])
    except lief.bad_file as err:
        print("Error: {0}".format(err))
        sys.exit(1)

    show_name(binary)
    enum_header(binary.header)
    enum_dyn_entries(binary)
    enum_dyn_relocs(binary)
    enum_exp_funcs(binary)
    enum_exp_symbols(binary)
    enum_imp_functions(binary)
    enum_imp_symbols(binary)
    enum_libraries(binary)
    show_notes(binary)
    show_interpreter(binary)
    enum_sections(binary)
    enum_segments(binary)

if __name__ == "__main__":
    run()
