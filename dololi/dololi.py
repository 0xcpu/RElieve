import lief
import sys
import os
import traceback
import configparser
import struct

from collections import OrderedDict


# Opcodes
X86_PUSH_BYTE     = 0x6a
X86_32_PUSH_DWORD = 0x68
x86_32_CALL       = [0xff, 0x15]
X86_64_CALL       = [0xff, 0xd0]
X86_64_MOV_R9     = [0x49, 0xb9]
X86_64_MOV_R8     = [0x49, 0xb8]
X86_64_MOV_RDX    = [0x48, 0xba]
X86_64_MOV_RCX    = [0x48, 0xb9]
X86_64_MOV_RAX    = [0x48, 0xc7, 0xc0]


def get_config(conf_file="dololi.conf"):
    assert os.path.isfile(conf_file)

    conf = configparser.ConfigParser()
    conf.read(conf_file)

    return conf


def is_dll(pe_file):
    return pe_file.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL)


def get_pe_type(arch):
    assert arch == "32" or arch == "64"
    
    if arch == "32":
        return lief.PE.PE_TYPE.PE32
    else:
        return lief.PE.PE_TYPE.PE32_PLUS


def is_64_bits(pe_type):
    return pe_type == lief.PE.PE_TYPE.PE32_PLUS


def get_reg_by_argn(argn):
    return {
        "1": "r9",
        "2": "r8",
        "3": "rdx",
        "4": "rcx",
        "5": "rax"
        }[argn]
    

def get_opcodes_by_reg(reg):
    return {
        "r9" : X86_64_MOV_R9,
        "r8" : X86_64_MOV_R8,
        "rdx": X86_64_MOV_RDX,
        "rcx": X86_64_MOV_RCX,
        "rax": X86_64_MOV_RAX
    }[reg]


def dololi(arch, conf, out_file_name):    
    code_rva  = int(conf["DEFAULT"].get("CODE_RVA"))
    data_rva  = int(conf["DEFAULT"].get("DATA_RVA"))
    pe_type   = get_pe_type(arch)
    is_64bits = is_64_bits(pe_type)
    pe_loader = lief.PE.Binary("dololi", pe_type)
    code_cnt,\
    reg_size,\
    pack_fmt = ([], 8, "<Q") if is_64bits else ([], 4, "<I")
    data_cnt = ""
    data_off = 0
    reg_cnt  = 1
    func_num = 0
    funcs    = OrderedDict()

    # Parse CODE and DATA contents from config file
    for k, v in conf["CODE"].items():
        if k.endswith("_byte"):
            value = int(v)
            value = struct.pack("<B", value)
            code_cnt.extend([X86_PUSH_BYTE, value[0]])
        elif k.endswith("_word"):
            value = int(v)
            value = struct.pack("<H", value)
            code_cnt.extend([X86_32_PUSH_DWORD, value[0], value[1], 0x0, 0x0])
        elif k.endswith("_dword") or k.endswith("_qword"):
            reg_size, pack_fmt = {"dword":(4, "<I"), "qword":(8, "<Q")}[k.split('_')[-1]]
            if v.lower().endswith("_data"):
                data_key = v.lower().rstrip("_data")
                assert "str" in data_key.lower(), "Data should contain arrays or strings"
                
                data_value = conf["DATA"][data_key] + '\0'
                data_cnt  += data_value

                addr = struct.pack(pack_fmt, pe_loader.optional_header.imagebase + data_rva + data_off)
                if is_64bits:
                    code_cnt.extend(get_opcodes_by_reg(get_reg_by_argn(str(reg_cnt))))
                    reg_cnt = (reg_cnt % 4) + 1
                    if reg_size < 8:
                        addr += bytes("\x00" * (8 - reg_size), 'ascii')
                    code_cnt.extend(list(addr))
                else:
                    code_cnt.extend([X86_32_PUSH_DWORD])
                    code_cnt.extend(list(addr))

                data_off += len(data_value)
            else:
                value = int(v)
                value = struct.pack(pack_fmt, value)
                if is_64bits:
                    code_cnt.extend(get_opcodes_by_reg(get_reg_by_argn(str(reg_cnt))))
                    reg_cnt = (reg_cnt  % 4) + 1
                    if reg_size < 8:
                        value += [0x0] * (8 - reg_size)
                    code_cnt.extend(list(value))
                else:
                    code_cnt.extend([X86_32_PUSH_DWORD])
                    code_cnt.extend(list(value))
        elif k.endswith("_func"):
            assert len(v.split(';')) == 2, "DLL name;Export function name"
            
            dll_name, export_name = v.strip("\r\n").split(';')
            dll = pe_loader.add_library(dll_name)
            dll.add_entry(export_name)
            
            func_num_str = "".join(["FUNC_", str(func_num)])
            if is_64bits:
                code_cnt.extend(get_opcodes_by_reg(get_reg_by_argn("5")))
                reg_cnt = (reg_cnt % 4) + 1
            else:
                code_cnt.extend(x86_32_CALL)
                
            for i in range(4):
                code_cnt.append(func_num_str)

            if is_64bits:
                code_cnt.extend(X86_64_CALL)
                
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
            func_addr = pe_loader.predict_function_rva(k, f[0])
            offset    = code_rva if func_num == 1 else 0 # dirty hack to adjust function address
            addr      = struct.pack(pack_fmt, pe_loader.optional_header.imagebase + data_rva - offset + func_addr)
            # TO DO, number of bytes should be adjusted automatically
            for i in range(4):
                code_cnt[code_cnt.index(f[1])] = addr[i]
    
    # set .text section fields
    text_sect                 = lief.PE.Section(".text")
    text_sect.virtual_address = code_rva
    text_sect.content         = code_cnt
    text_sect                 = pe_loader.add_section(text_sect, lief.PE.SECTION_TYPES.TEXT)
    # set .data section fields
    data_sect                 = lief.PE.Section(".data")
    data_sect.virtual_address = data_rva
    data_sect.content         = list(map(ord, data_cnt))
    data_sect                 = pe_loader.add_section(data_sect, lief.PE.SECTION_TYPES.DATA)

    pe_loader.optional_header.addressof_entrypoint = text_sect.virtual_address
        
    builder = lief.PE.Builder(pe_loader)
    builder.build_imports(True)
    builder.build()
    builder.write(out_file_name)

    print("{0} was successfully created!".format(out_file_name))

    
if __name__ == "__main__":
    assert len(sys.argv) > 1, "Usage: {0} <32|64> [Output file name]".format(sys.argv[0])

    if sys.argv[1] not in ("32", "64"):
        print("Use 32 to build x86_32 bit or 64 for x86_64 bit loader")

        sys.exit(1)

    dololi(sys.argv[1], get_config(), "dololi.exe" if len(sys.argv) < 3 else sys.argv[2])
