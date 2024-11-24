#
# Copyright (C) 2022 Gal Kristal, Dina Teper
# Copyright (C) 2022 SentinelOne, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import math
import struct
import random
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import asm_stubs
import pefilemod

g_csd = Cs(CS_ARCH_X86, CS_MODE_64)
g_csd.detail = True

IS_EXECUTABLE = lambda s: bool(s.Characteristics & pefilemod.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) \
    if hasattr(s, 'Characteristics') else False
ALIGN_RVA = lambda v: int(
    math.ceil(v / float(g_binary.OPTIONAL_HEADER.SectionAlignment))) * g_binary.OPTIONAL_HEADER.SectionAlignment
ALIGN_RAW = lambda v: int(math.ceil(v / float(g_binary.OPTIONAL_HEADER.FileAlignment))) * g_binary.OPTIONAL_HEADER.FileAlignment
GET_SEC_BY_NAME = lambda v: [s for s in g_binary.sections if s.Name.startswith(v)][0]

def PAGE_ALIGN(addr):
    if addr % 0x1000 == 0:
        return addr
    return (addr + (0x1000 - addr % 0x1000))

def GET_SEC_BY_ADDR(addr):
    for s in g_binary.sections:
        if addr >= s.VirtualAddress and addr < PAGE_ALIGN(s.VirtualAddress + s.Misc_VirtualSize):
            return s

def GET_SEC_BY_RAW(addr):
    for s in g_binary.sections:
        if addr >= s.PointerToRawData and addr <= s.PointerToRawData + s.SizeOfRawData:
            return s

def GET_RAW_BY_RVA(addr):
    s = GET_SEC_BY_ADDR(addr)
    return s.PointerToRawData + addr - s.VirtualAddress

def GET_RVA_BY_RAW(addr):
    s = GET_SEC_BY_RAW(addr)
    return s.VirtualAddress + addr - s.PointerToRawData

def READ_RAW_BYTE(addr):
    global g_binary
    return u8(g_binary.__data__[addr:addr+1])

def WRITE_RAW_BYTE(addr, value):
    global g_binary
    g_binary.__data__[addr:addr+1] = p8(value)
    return

def READ_RAW_DWORD(addr):
    global g_binary
    return u32(g_binary.__data__[addr:addr+4])

def WRITE_RAW_DWORD(addr, value):
    global g_binary
    g_binary.__data__[addr:addr+4] = p32(value)
    return

def pb8(addr):
    return struct.pack(">B", addr)

def p8(addr):
    return pb8(addr)

def u8(addr):
    return struct.unpack(">B", addr)[0]

def pb16(addr):
    return struct.pack(">H", addr)

def p32(addr):
    return struct.pack("<I", addr)

def u32(addr):
    return struct.unpack("<I", addr)[0]

def pb32(addr):
    return struct.pack(">I", addr)


def p64(addr):
    return struct.pack("<Q", addr)

def pb64(addr):
    return struct.pack(">Q", addr)

ENLARGE_MULTIPLE = 8 # increase this if binary has many small blocks
SAVE_BYTES_SIZE = 0x100 # increase this if binary has many executable sections

g_binary_path = ""
g_binary = None
g_ida_data = None
g_first_section_raw = 0
g_saved_bytes = b""
g_section_mapping = {}

def duplicate_binary(binary_path) -> str:
    """
    Copy binary
    :return: path to copied binary
    """
    global g_binary_path

    g_binary_path = binary_path.split(".")[0] + "_instrumented." + binary_path.split(".")[1]

    f = open(binary_path, "rb")
    f_copy = open(g_binary_path, "wb+")
    f_copy.write(f.read())
    f.close()
    f_copy.close()
    
    return g_binary_path

def load_binary(binary_path) -> None:
    """
    Load binary and extract PE information
    :return: None
    """
    global g_binary

    g_binary = pefilemod.PE(binary_path)

    return

def flush_binary() -> None:
    """
    Close pefile object and reopen
    :return: None
    """
    global g_binary
    global g_binary_path

    g_binary.close()
    load_binary(g_binary_path)


def commit_binary() -> None:
    """
    Close pefile object
    :return: None
    """
    global g_binary
    global g_binary_path

    g_binary.close()
    

def load_ida_data(ida_data_path) -> None:
    """
    Load IDA instrumentation data
    :return: None
    """
    global g_ida_data

    with open(ida_data_path) as f:
        g_ida_data = json.load(f)

    # json does not support using integers as keys so when dumping it from IDA it gets
    # converted into strings automatically. We need to convert it back to integers for later use
    for key in list(g_ida_data['relative'].keys()):
        g_ida_data['relative'][int(key)] = g_ida_data['relative'].pop(key)
    for key in list(g_ida_data['rip_relative'].keys()):
        g_ida_data['rip_relative'][int(key)] = g_ida_data['rip_relative'].pop(key)
    for key in list(g_ida_data['functions'].keys()):
        g_ida_data['functions'][int(key)] = g_ida_data['functions'].pop(key)
        g_ida_data['bb'].append(int(key))
    for key in list(g_ida_data['jmptables'].keys()):
        g_ida_data['jmptables'][int(key)] = g_ida_data['jmptables'].pop(key)

    return

def try_clear_overlay() -> None:
    """
    Removes certificate section(overlay), which is the last section of the binary
    :return: None
    """
    global g_binary

    # remove certificate if needed
    security_dir = g_binary.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_SECURITY')
    if security_dir.VirtualAddress:
        clear_overlay(security_dir)

    return

def clear_overlay(security_dir) -> None:
    """
    Remove the certificate from the PE so we can add new sections behind
    :return: None
    """
    global g_binary
    global g_binary_path

    entry_size_old = security_dir.Size

    security_dir.VirtualAddress = 0
    security_dir.Size = 0

    # truncate binary
    g_binary.write(g_binary_path, append=None, cut=entry_size_old)
    flush_binary()

    print("[*] Cleared overlay")

    return

def make_new_segments() -> None:
    """
    Duplicate all executable segments, enlarging all by ENLARGE_MULTIPLE times
    Make .cov segment for code coverage
    :return: None
    """
    global g_binary
    global g_binary_path
    global g_first_section_raw
    global g_saved_bytes

    # first save some bytes from the first section, in case section table overwrites into it
    g_binary.sections.sort(key=lambda s: s.PointerToRawData)
    g_first_section_raw = g_binary.sections[0].PointerToRawData
    g_saved_bytes = g_binary.__data__[g_first_section_raw:g_first_section_raw+SAVE_BYTES_SIZE]

    for orig_sec in g_binary.sections.copy():
        if IS_EXECUTABLE(orig_sec) and orig_sec.SizeOfRawData != 0:
            duplicate_segment(orig_sec, ENLARGE_MULTIPLE)

    # Get some space for CFG table
    rdata_seg = GET_SEC_BY_NAME(b".rdata")
    duplicate_segment(rdata_seg, name=b".cfg", size=0x3000)

    # Use data segment as template for .cov segment
    data_seg = GET_SEC_BY_NAME(b".data")
    duplicate_segment(data_seg, name=b".cov", size=0x1000)

    g_binary.OPTIONAL_HEADER.SizeOfImage, _, _ = get_new_section_rva_raw_entry()

    g_binary.write(g_binary_path)
    flush_binary()

def duplicate_segment(original, enlarge_by=0, name=None, size=0) -> None:
    """
    Duplicate a segment either with a custom name and size
    Or append "2" behind original name and enlarge original size by ENLARGE_MULTIPLE
    :return: None
    """
    global g_binary
    global g_binary_path
    global g_section_mapping

    new_section = pefilemod.SectionStructure(g_binary.__IMAGE_SECTION_HEADER_format__, pe=g_binary)
    # Copy the original section attributes to the duplicated section
    new_section.__unpack__(original.__pack__())

    # Set name and attributes
    if name:
        new_section.Name = name.ljust(8, b'\x00')
    else:
        new_section.Name = original.Name.replace(b"\x00", b"2", 1) # .text -> .text2
    rva, raw, entry = get_new_section_rva_raw_entry()
    new_section.VirtualAddress = rva
    new_section.PointerToRawData = raw
    new_section.set_file_offset(entry)

    if size:
        new_section_size = size
    else:
        new_section_size = original.SizeOfRawData * enlarge_by

    new_section.SizeOfRawData = ALIGN_RAW(new_section_size)
    new_section.Misc_VirtualSize = ALIGN_RVA(new_section_size)
    new_section.next_section_virtual_address = new_section.VirtualAddress + new_section.Misc_VirtualSize

    g_binary.__structures__.append(new_section)
    g_binary.sections.append(new_section)
    g_binary.FILE_HEADER.NumberOfSections += 1
    g_section_mapping.update({original.Name: new_section.Name})

    extension_padding = b"\x00" * new_section.SizeOfRawData
    g_binary.write(g_binary_path, append=extension_padding)
    flush_binary()

    print("[*] Duplicated section " + \
          original.Name.split(b"\x00")[0].decode() + \
          " -> " + new_section.Name.split(b"\x00")[0].decode())

    return
    
def get_new_section_rva_raw_entry() -> (int, int, int):
    """
    Finds next new possible RVA, PtrToRawData and section header update offset for new section
    :return: (rva, raw, entry)
    """
    global g_binary

    rva = 0
    raw = 0
    entry = 0
    for sec in g_binary.sections:
        rva = max(rva, sec.VirtualAddress + sec.Misc_VirtualSize)
        raw = max(raw, sec.PointerToRawData + sec.SizeOfRawData)
        entry = max(entry, sec.get_file_offset() + sec.sizeof())

    return ALIGN_RVA(rva), ALIGN_RAW(raw), entry


g_bb_list = []
g_current_section = None
g_current_available_raw = 0 # current available address to slot bb
g_current_available_rva = 0 # current available rva to slot bb
DUMMY_ADDR = pb32(0xdeadbeef)

class INS_ID:
    def __init__(self, ins_type, ins_loc, ins_metadata):
        self.ins_type = ins_type
        self.ins_loc = ins_loc
        self.ins_metadata = ins_metadata

class INS:
    def __init__(self, old_dest, ins_offset, bb_addr_offset, new_size):
        self.old_dest = old_dest
        self.ins_offset = ins_offset
        self.bb_addr_offset = bb_addr_offset
        self.new_size = new_size

class BB:
    def __init__(self, orig_rva, orig_size, shellcode):
        global g_binary
        global g_ida_data
        global g_current_section
        global g_current_available_raw
        global g_current_available_rva
        global g_first_section_raw
        global g_saved_bytes
        global g_section_mapping
        global g_exception_addresses_to_update

        self.orig_rva = orig_rva
        self.orig_size = orig_size
        # see where to slot bb
        orig_section = GET_SEC_BY_ADDR(self.orig_rva)
        self.orig_raw = GET_RAW_BY_RVA(self.orig_rva)
        if g_current_section != orig_section:
            new_sec_name = g_section_mapping[orig_section.Name]
            new_sec = GET_SEC_BY_NAME(new_sec_name)
            g_current_section = orig_section
            g_current_available_raw = new_sec.PointerToRawData
            g_current_available_rva = new_sec.VirtualAddress
        
        self.new_raw = g_current_available_raw
        self.new_rva = g_current_available_rva

        # get all exception addresses related to this bb
        all_ex = []
        for ex in g_exception_addresses_to_update:
            if ex.orig_rva < self.orig_rva:
                continue

            if ex.orig_rva >= self.orig_rva + self.orig_size:
                break

            ex.bb_orig_rva = self.orig_rva
            ex.new_offset_in_bb = ex.orig_rva - ex.bb_orig_rva + len(shellcode)
            all_ex.append(ex)
       
        # replace magic in shellcode
        cov_area = GET_SEC_BY_NAME(b".cov").VirtualAddress
        offset = self.new_rva + shellcode.find(p32(asm_stubs.M_AREA_PTR)) + 4
        offset = cov_area - offset
        shellcode = shellcode.replace(p32(asm_stubs.M_AREA_PTR), p32(offset))

        prev_loc_area = cov_area + 0x10
        offset = self.new_rva + shellcode.find(p32(asm_stubs.M_PREV_LOC)) + 4
        offset = prev_loc_area - offset
        shellcode = shellcode.replace(p32(asm_stubs.M_PREV_LOC), p32(offset), 1)

        # two prev locs to replace
        offset = self.new_rva + shellcode.find(p32(asm_stubs.M_PREV_LOC)) + 4
        offset = prev_loc_area - offset
        shellcode = shellcode.replace(p32(asm_stubs.M_PREV_LOC), p32(offset), 1)

        pid_area = cov_area + 0x20
        offset = self.new_rva + shellcode.find(p32(asm_stubs.M_PID)) + 4
        offset = pid_area - offset
        shellcode = shellcode.replace(p32(asm_stubs.M_PID), p32(offset))

        random_val = random.randint(0,0x10000-1)
        shellcode = shellcode.replace(p64(asm_stubs.C_ADDR1), p64(random_val))
        shellcode = shellcode.replace(p64(asm_stubs.C_ADDR2), p64(random_val >> 1))
        # parse out original bb data from PE
        self.data = g_binary.__data__[self.orig_raw:self.orig_raw+orig_size]

        # if BB contains data potentially overwritten by section table, retrieve from cache
        for i in range(self.orig_raw, self.orig_raw+orig_size):
            if i in range(g_first_section_raw, g_first_section_raw + SAVE_BYTES_SIZE):
                self.data[i-self.orig_raw] = g_saved_bytes[i-g_first_section_raw]

        # add shellcode
        self.data = shellcode + self.data

        self.relative_ins = []
        self.rip_relative_ins = []

        all_ins_list = []

        # get all relatives and rip_relatives in current BB
        for ins_loc, ins_metadata in g_ida_data["relative"].items():
            if ins_loc < self.orig_rva or ins_loc >= self.orig_rva + self.orig_size:
                continue
            all_ins_list.append(INS_ID("relative", ins_loc, ins_metadata))

        for ins_loc, ins_metadata in g_ida_data["rip_relative"].items():
            if ins_loc < self.orig_rva or ins_loc >= self.orig_rva + self.orig_size:
                continue
            all_ins_list.append(INS_ID("rip_relative", ins_loc, ins_metadata))

        # sort by addr
        all_ins_list.sort(key=lambda x: x.ins_loc)

        # expand ins
        increased_size = len(shellcode)
        for ins in all_ins_list:
            if ins.ins_type == "relative":
                # get offset in new BB
                ins_offset = increased_size + (ins.ins_loc - self.orig_rva)
                ins_dest = ins.ins_metadata[0]
                ins_operator = int(ins.ins_metadata[1], 16)
                ins_operator_size = ins.ins_metadata[2]
                ins_old_size = ins.ins_metadata[3]

                # expand operators
                if ins_operator_size == 1:
                    new_operator = pb8(ins_operator)
                elif ins_operator_size == 2:
                    new_operator = pb16(ins_operator)
                else:
                    print("not implemented relative ins size!: " + hex(ins_operator_size))
                if ins_operator > 0x6f and ins_operator < 0x80:
                    # JE/JNE/J0... class
                    new_operator = pb16(ins_operator + 0x0f10) # JE(74) rel8 -> JE(ff 84) rel32

                elif ins_operator == 0xE3:
                    # JCXZ cb -> test ecx, ecx; JZ rel32
                    new_operator = pb16(0x85c9) # test ecx, ecx
                    new_operator += pb16(0x0f84) # JZ rel32

                elif ins_operator == 0xEB:
                    # JMP rel8 -> JMP rel32
                    new_operator = pb8(0xE9)

                # loop instructions are dumb, we have to expand to test and jump
                elif ins_operator == 0xE0:
                    test_operator = pb16(0x85c9) # test ecx, ecx
                    test_operator += pb16(0x0f85) # JNZ rel32
                    # LOOPNZ rel8 -> JZ (after test); test ecx, ecx; JNZ rel32
                    new_operator = pb8(0x74)
                    new_operator += pb8(len(test_operator) + len(DUMMY_ADDR))
                    new_operator += test_operator

                elif ins_operator == 0xE1:
                    test_operator = pb16(0x85c9) # test ecx, ecx
                    test_operator += pb16(0x0f84) # JNZ rel32
                    # LOOPNZ rel8 -> JNZ (after test); test ecx, ecx; JNZ rel32
                    new_operator = pb8(0x75)
                    new_operator += pb8(len(test_operator) + len(DUMMY_ADDR))
                    new_operator += test_operator

                elif ins_operator == 0xE2:
                    test_operator = pb16(0x85c9) # test ecx, ecx
                    test_operator += pb16(0x0f84) # JNZ rel32
                    # LOOP rel8 -> test ecx, ecx; JNZ rel32
                    new_operator = test_operator
                
                self.data = self.data[:ins_offset] + new_operator + DUMMY_ADDR + self.data[ins_offset+ins_old_size:]
                delta = (len(new_operator) + len(DUMMY_ADDR) - ins_old_size)
                # this may affect offset of exception addresses, so we update them
                for ex in all_ex:
                    if ins_offset < ex.new_offset_in_bb:
                        ex.new_offset_in_bb += delta 

                increased_size += delta
                
                
                # add to bb instructions list
                self.relative_ins.append(INS(ins_dest, ins_offset, ins_offset+len(new_operator), len(new_operator)+len(DUMMY_ADDR)))

            else:
                # for rip-relative, just update offset will do
                ins_offset = increased_size + (ins.ins_loc - self.orig_rva)
                ins_dest = ins.ins_metadata[0]
                ins_full = ins.ins_metadata[1]
                ins_length = ins.ins_metadata[3]

                ins_obj = next(g_csd.disasm(bytes.fromhex(ins_full), 0))

                self.data = self.data[:ins_offset+ins_obj.disp_offset] + DUMMY_ADDR + self.data[ins_offset+ins_obj.disp_offset+len(DUMMY_ADDR):]
                self.rip_relative_ins.append(INS(ins_dest, ins_offset, ins_offset+ins_obj.disp_offset, ins_length))

        self.data += b"\x90"*(0x10-len(self.data)%0x10) # 16 byte align

        g_current_available_raw += len(self.data)
        g_current_available_rva += len(self.data)

        # make sure we don't write into other sections
        assert GET_SEC_BY_ADDR(g_current_available_rva).Name == g_section_mapping[g_current_section.Name], "Too many BBs! Increase enlarge multiple"

        return

g_rva_mapping = {}
def inject_into_bb(shellcode) -> None:
    """
    For all bb dumped from IDA, parse and store in BB list
    In the process, inject whatever shellcode provided before each bb
    :return: None
    """
    global g_ida_data
    global g_bb_list
    global g_rva_mapping

    # first load list of exception handled addresses
    # so we can be protected by exception handling even after instrumentation
    prepare_exception_list()

    g_ida_data["bb"] = sorted(list(set(g_ida_data["bb"])))

    for bb_idx in range(len(g_ida_data["bb"])):
        bb_raw = g_ida_data["bb"][bb_idx]

        bb_size = 0
        if bb_idx + 1 == len(g_ida_data["bb"]):
            # for last bb, take length as up to end of function
            for start, end in g_ida_data["functions"].items():
                if bb_raw < start or bb_raw > end:
                    continue
                bb_size = end - bb_raw
        else:
            # for all other bbs, take length as delta from next bb
            # unless they are not in the same section, then take length as delta from end of function
            if GET_SEC_BY_ADDR(g_ida_data["bb"][bb_idx]) != GET_SEC_BY_ADDR(g_ida_data["bb"][bb_idx+1]):
                for start, end in g_ida_data["functions"].items():
                    if bb_raw < start or bb_raw > end:
                        continue
                    bb_size = end - bb_raw
            else:
                bb_size = g_ida_data["bb"][bb_idx+1] - bb_raw
        
        if bb_idx % 1000 == 0:
            print(f"[*] Processing {bb_idx}/{len(g_ida_data['bb'])}")
        g_bb_list.append(BB(bb_raw, bb_size, shellcode))
    
    print("[*] Finish injecting instrumentation into all bb")
    for bb in g_bb_list:
        g_rva_mapping.update({bb.orig_rva: bb.new_rva})

    return

def bb_get_new_addr_from_old(old_addr) -> int:
    """
    Get updated rva in instrumented section
    If not found means target has not been changed
    :return: new rva
    """
    global g_rva_mapping

    try:
        return g_rva_mapping[old_addr]
    except:
        return old_addr

g_exception_addresses_to_update = []

UNW_FLAG_EHANDLER = 1
UNW_FLAG_UHANDLER = 2
UNW_FLAG_CHAININFO = 4

class ExceptionAddressUpdateInfo:
    def __init__(self, orig_rva, update_raw_offset):
        self.orig_rva = orig_rva
        self.update_raw_offset = update_raw_offset
        self.bb_orig_rva = 0
        self.new_offset_in_bb = 0

def prepare_exception_list() -> None:
    """
    Collate all addresses related to exception handling
    :return: None
    """
    global g_binary
    global g_exception_addresses_to_update
    global g_ida_data
    
    exception_dir = g_binary.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_EXCEPTION')
    exception_entry_size = 3 * 4
    scope_table_entry_size = 4 * 4
    start = exception_dir.VirtualAddress
    start_raw = GET_RAW_BY_RVA(start)
    end_raw = start_raw + exception_dir.Size

    while start_raw < end_raw:
        unwind_raw = add_exception_begin_end(start_raw)
        unwind_flag = READ_RAW_BYTE(unwind_raw)
        unwind_code_count = READ_RAW_BYTE(unwind_raw + 2)

        while unwind_flag & UNW_FLAG_CHAININFO:
            # chained unwind info
            chained_unwind_raw_start = unwind_raw + 4 + ((unwind_code_count + 1) &~ 1) * 2
            unwind_raw = add_exception_begin_end(chained_unwind_raw_start)
            unwind_flag = READ_RAW_BYTE(unwind_raw)
            unwind_code_count = READ_RAW_BYTE(unwind_raw + 2)

        # regular unwind info
        # for our case it's not necessary to differentiate between exception and termination handler
        if  (unwind_flag >> 3) & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            unwind_handler_start = unwind_raw + 4 + ((unwind_code_count+1)&~1) * 2
            unwind_handler = READ_RAW_DWORD(unwind_handler_start)

            # deal with different unwind handlers differently
            if unwind_handler == g_ida_data["gs_handler"]:
                 # at time of writing this doesn't require treatment
                pass

            elif unwind_handler == g_ida_data["c_handler"] or \
                 unwind_handler == g_ida_data["gs_handler_seh"]:
                WRITE_RAW_DWORD(unwind_handler_start, g_ida_data["c_handler"])
                # at time of writing both require the same treatment
                # c_handler contains a scope table
                # gs_handler_seh contains a scope table followed by gs specific data(no need update)
                scope_table_raw = unwind_handler_start + 4
                scope_table_data_raw = scope_table_raw + 4
                num_entries = READ_RAW_DWORD(scope_table_raw)

                for _ in range(num_entries):
                    begin = READ_RAW_DWORD(scope_table_data_raw)
                    g_exception_addresses_to_update.append(ExceptionAddressUpdateInfo(begin, scope_table_data_raw))
                    
                    end = READ_RAW_DWORD(scope_table_data_raw+4)
                    g_exception_addresses_to_update.append(ExceptionAddressUpdateInfo(end, scope_table_data_raw+4))
                    
                    handler = READ_RAW_DWORD(scope_table_data_raw+8)
                    if handler and handler != 1:
                        # for EXCEPTION_EXECUTE_HANDLER, handler == 1
                        g_exception_addresses_to_update.append(ExceptionAddressUpdateInfo(handler, scope_table_data_raw+8))

                    target = READ_RAW_DWORD(scope_table_data_raw+12)
                    if target:
                        # for __finally blocks, target == 0
                        g_exception_addresses_to_update.append(ExceptionAddressUpdateInfo(target, scope_table_data_raw+12))

                    scope_table_data_raw += scope_table_entry_size

            else:
                print(f"[*] Warning: Exception handler not implemented -> {hex(unwind_handler)}")

        start_raw += exception_entry_size

    g_exception_addresses_to_update.sort(key = lambda x: x.orig_rva)
    return

def add_exception_begin_end(start_raw) -> int:
    """
    Adds exception begin and end address to global list
    :return: Raw address for unwind information related to this pair of (begin, end)
    """
    global g_binary
    global g_exception_addresses_to_update

    exception_begin = READ_RAW_DWORD(start_raw)
    exception_end = READ_RAW_DWORD(start_raw+4)
    unwind_raw = READ_RAW_DWORD(start_raw+8)
        
    g_exception_addresses_to_update.append(ExceptionAddressUpdateInfo(exception_begin, start_raw))
    g_exception_addresses_to_update.append(ExceptionAddressUpdateInfo(exception_end, start_raw+4))

    return GET_RAW_BY_RVA(unwind_raw)

def fix_jumps() -> None:
    """
    Write fixed jump offsets into bb's data blob
    :return: None
    """
    global g_bb_list
    global g_binary
    global g_binary_path

    for bb in g_bb_list:
        # fix both relative and rip_relative the same way
        for ins in bb.relative_ins + bb.rip_relative_ins:
            new_addr = bb_get_new_addr_from_old(ins.old_dest)
            # write into bb's data
            ins_abs_offset = ins.ins_offset + bb.new_rva
            bb.data[ins.bb_addr_offset:ins.bb_addr_offset+4] = p32((((new_addr-ins_abs_offset)&0xffffffff)-ins.new_size)&0xffffffff)

    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Fixed jumps")

    return


def write_bb() -> None:
    """
    Write bb data into pe
    :return: None
    """
    global g_bb_list
    global g_binary
    global g_binary_path

    for bb_idx in range(len(g_bb_list)):
         if bb_idx % 1000 == 0:
            print(f"[*] Writing {bb_idx}/{len(g_bb_list)}")
         g_binary.__data__[g_bb_list[bb_idx].new_raw:g_bb_list[bb_idx].new_raw+len(g_bb_list[bb_idx].data)] = g_bb_list[bb_idx].data

    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Written bb into binary")

    return

def fix_exports() -> None:
    """
    Fix export table with updated offsets
    :return: None
    """
    global g_binary
    global g_binary_path

    if not hasattr(g_binary, "DIRECTORY_ENTRY_EXPORT"):
        return

    for export_entry in g_binary.DIRECTORY_ENTRY_EXPORT.symbols:
        if export_entry.address:
            WRITE_RAW_DWORD(export_entry.address_offset, bb_get_new_addr_from_old(export_entry.address))
    
    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Fixed export table")

    return

def fix_entrypoint(orig_main_rva, rvas_to_update) -> None:
    """
    Fix hardcoded calls
    For example, GsDriverEntry is hardcoded to call uninstrumented DriverEntry
    This leads to uninstrumented DriverEntry registering uninstrumented handler functions

    We can patch that to call our own driverentry
    Since we do this, we don't have to patch AddressOfEntryPoint in driver header

    orig_main_rva -> DriverEntry address
    rvas_to_update -> List of call instructions to DriverEntry

    Applies to exe/dll as well
    :return: None
    """
    global g_binary
    global g_binary_path

    if not orig_main_rva or not rvas_to_update:
        return

    new_main_rva = bb_get_new_addr_from_old(orig_main_rva)
    for rva in rvas_to_update:
        new_delta = (((new_main_rva-rva)&0xffffffff)-5)&0xffffffff # 5 -> size of call instruction
        update_point = GET_RAW_BY_RVA(rva + 1) # skip the E8 call instruction
        WRITE_RAW_DWORD(update_point, new_delta)
    
    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Updated entrypoints")

    return

def fix_entrypoint_auto() -> None:
    global g_binary
    global g_binary_path

    g_binary.OPTIONAL_HEADER.AddressOfEntryPoint = bb_get_new_addr_from_old(g_binary.OPTIONAL_HEADER.AddressOfEntryPoint)
    
    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Updated entrypoints automatically")

    return

def fix_jumptables() -> None:
    global g_binary
    global g_binary_path
    global g_ida_data

    for jump_target, jmp_info in g_ida_data['jmptables'].items():
        new_target = bb_get_new_addr_from_old(jump_target)
        for src, size, base in jmp_info:
            WRITE_RAW_DWORD(src, new_target - base)
    
    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Fixed jumptables")

    return

def fix_exceptions() -> None:
    """
    Just write all addresses related to exception back to binary
    :return: None
    """
    global g_binary
    global g_binary_path
    global g_exception_addresses_to_update

    for ex in g_exception_addresses_to_update:
        if not ex.bb_orig_rva or not ex.new_offset_in_bb:
            # some BBs are isolated and not instrumented, that's fine
            continue

        new_bb_rva = bb_get_new_addr_from_old(ex.bb_orig_rva)
        new_exception_addr = new_bb_rva + ex.new_offset_in_bb
        WRITE_RAW_DWORD(ex.update_raw_offset, new_exception_addr)
    
    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Updated exception table")

    return

def fix_cfg() -> None:
    """
    Update CFG table, add instrumented functions
    :return: None
    """
    global g_binary
    global g_binary_path

    count = g_binary.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount
    if not count:
        return
    
    cfg_seg = GET_SEC_BY_NAME(b".cfg")
    to_update = []
    
    start = g_binary.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable - g_binary.OPTIONAL_HEADER.ImageBase
    start_raw = GET_RAW_BY_RVA(start)
    entry_size = ((g_binary.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags & 0xF0000000) >> 28) + 4
    update_raw = cfg_seg.PointerToRawData
    update_offset = 0

    for i in range(count):
        old_rva = READ_RAW_DWORD(start_raw + i * entry_size)
        new_rva = bb_get_new_addr_from_old(old_rva)
        if old_rva != new_rva:
            to_update.append(new_rva)

        WRITE_RAW_DWORD(update_raw + update_offset * entry_size, old_rva)
        update_offset += 1

    for new_rva in to_update:
        WRITE_RAW_DWORD(update_raw + update_offset * entry_size, new_rva)
        update_offset += 1

    g_binary.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount += len(to_update)
    g_binary.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable = g_binary.OPTIONAL_HEADER.ImageBase + GET_RVA_BY_RAW(update_raw)

    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Updated CFG table")

    return

def fix_checksum() -> None:
    """
    Recalculate and update PE file's checksum
    :return: None
    """
    global g_binary
    global g_binary_path
    
    if not g_binary.OPTIONAL_HEADER.CheckSum:
        return

    g_binary.OPTIONAL_HEADER.CheckSum = g_binary.generate_checksum()
    g_binary.write(g_binary_path)
    flush_binary()

    print("[*] Fixed checksum")

    return
