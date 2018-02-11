import lief
import sys
import os
import traceback
import configparser
import struct

from collections import OrderedDict

# assembly opcodes for 32 bit version
CODE_X86_32 = [
    0x6a, None,
    0x68, None, None, None, None,
    0x68, None, None, None, None,
    0x6a, None,
    0xff, 0x15, None, None, None, None,
    0x6a, None,
    0xff, 0x15, None, None, None, None
]
# assembly opcodes for 64 bit version
CODE_X86_64 = [
    0x49, 0xb9, None, None, None, None, None, None, None, None,
    0x49, 0xb8, None, None, None, None, None, None, None, None,
    0x48, 0xba, None, None, None, None, None, None, None, None,
    0x48, 0xb9, None, None, None, None, None, None, None, None,
    0x48, 0xc7, 0xc0, None, None, None, None,
    0xff, 0xd0,
    0x48, 0xb9, None, None, None, None, None, None, None, None,
    0x48, 0xc7, 0xc0, None, None, None, None,
    0xff, 0xd0
]


def get_config(conf_file="dololi.conf"):
    assert os.path.isfile(conf_file)

    conf = configparser.ConfigParser()
    conf.read(conf_file)

    return conf


def is_dll(pe_file):
    return pe_file.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL)


def get_pe_type(pe_file):
    return pe_file.optional_header.magic


def is_64_bits(pe_type):
    return pe_type == lief.PE.PE_TYPE.PE32_PLUS


def dololi(file_name, conf, out_file_name):
    if not os.path.isfile(file_name):
        print("{0} is not a regular file".format(file_name), file=sys.stderr)

        return

    try:
        pe_file = lief.PE.parse(file_name)
    except lief.bad_format as _:
        traceback.print_exc()

        return

    if not is_dll(pe_file):
        print("{0} is not a DLL".format(file_name), file=sys.stderr)

        return
    
    code_rva = int(conf["DEFAULT"].get("CODE_RVA"))
    data_rva = int(conf["DEFAULT"].get("DATA_RVA"))
    pe_type  = get_pe_type(pe_file)
    pe_load  = lief.PE.Binary("dololi", pe_type)
    code_cnt,\
    reg_size,\
    pack_fmt = (CODE_X86_64, 8, "<Q") if is_64_bits(pe_type) else (CODE_X86_32, 4, "<I")
    data_cnt = ""
    data_off = 0
    func_num = 0
    funcs    = OrderedDict()

    # Parse CODE and DATA contents from config file
    for k, v in conf["CODE"].items():
        if k.endswith("_byte"):
            value = int(v)
            value = struct.pack("<B", value)
            code_cnt[code_cnt.index(None)] = value[0]
        elif k.endswith("_word"):
            value = int(v)
            value = struct.pack("<H", value)
            code_cnt[code_cnt.index(None)] = value[0]
            code_cnt[code_cnt.index(None)] = value[1]
        elif k.endswith("_dword") or k.endswith("_qword"):
            reg_size, pack_fmt = {"dword":(4, "<I"), "qword":(8, "<Q")}[k.split('_')[-1]]
            if v.lower().endswith("_data"):
                data_key   = v.lower().rstrip("_data")
                assert "str" in data_key.lower(), "Data should contain arrays or strings"
                
                data_value = conf["DATA"][data_key] + '\0'
                data_cnt  += data_value

                addr = struct.pack(pack_fmt, pe_load.optional_header.imagebase + data_rva + data_off)
                for i in range(reg_size):
                    code_cnt[code_cnt.index(None)] = addr[i]

                data_off += len(data_value)
            else:
                value = int(v)
                value = struct.pack(pack_fmt, value)
                for i in range(reg_size):
                    code_cnt[code_cnt.index(None)] = value[i]
        elif k.endswith("_func"):
            assert len(v.split(';')) == 2, "DLL name;Export function name"
            
            dll_name, export_name = v.strip("\r\n").split(';')
            dll = pe_load.add_library(dll_name)
            dll.add_entry(export_name)
            
            func_num_str = "".join(["FUNC_", str(func_num)])
            for i in range(4):
                code_cnt[code_cnt.index(None)] = func_num_str

            if dll_name not in funcs:
                funcs[dll_name] = set()

            funcs[dll_name].add((export_name, func_num_str))
            func_num += 1
        else:
            # code_rva and data_rva from DEFAULT section
            pass

    # Add function addresses
    for k, v in funcs.items():
        for f in v:
            func_addr = pe_load.predict_function_rva(k, f[0])
            addr = struct.pack(pack_fmt, pe_load.optional_header.imagebase + data_rva + func_addr)
            # TO DO, number of bytes should be adjusted automatically
            for i in range(4):
                code_cnt[code_cnt.index(f[1])] = addr[i]
            
    # set .text section fields
    text_sect                 = lief.PE.Section(".text")
    text_sect.virtual_address = code_rva
    text_sect.content         = code_cnt
    text_sect                 = pe_load.add_section(text_sect, lief.PE.SECTION_TYPES.TEXT)
    # set .data section fields
    data_sect                 = lief.PE.Section(".data")
    data_sect.virtual_address = data_rva
    data_sect.content         = list(map(ord, data_cnt))
    data_sect                 = pe_load.add_section(data_sect, lief.PE.SECTION_TYPES.DATA)

    pe_load.optional_header.addressof_entrypoint = text_sect.virtual_address
    
    builder = lief.PE.Builder(pe_load)
    builder.build_imports(True)
    builder.build()
    builder.write(out_file_name)

    print("{0} was successfully created!".format(out_file_name))

    
if __name__ == "__main__":
    assert len(sys.argv) > 1, "Usage: {0} <DLL file> [Output file name]".format(sys.argv[0])

    dololi(sys.argv[1], get_config(), "dololi.exe" if len(sys.argv) < 3 else sys.argv[2])
