import json
import re

import idaapi
import idc
from typing import List, Dict
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from idautils import ida_bytes, Functions, Heads, Segments

## Globals
g_basic_blocks: List = []
g_jmp_tbls: Dict = {}
g_relative_instructions: Dict = {}
g_rip_relative_instructions: Dict = {}
f_c_handler, f_gs_handler, f_gs_handler_seh = None, None, None
g_funcs: Dict = {} # function {start, end} addresses

# Global disassembler object
g_disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
g_disassembler.detail = True

## lambdas ##
# Byte array to hex repr in python2
ba2hex = lambda ba: "".join("%02x" % b for b in ba)

## Constants
BASIC_BLOCK_COLOR = 0x6699ff
EXPLICITLY_INCLUDED_COLOR = 0xffffff
EXPLICITLY_EXCLUDED_COLOR = 0x0

def parse_relative(ea):
    """
    Identify if the asm code at the given address contains a relative command
    :param ea: Address to test
    :return: (command in hex bytes, offset in hex bytes)
    """
    buf = idc.get_bytes(ea, idc.get_item_size(ea))
    idx = 0
    mpx_candidate = False

    # call (e8), http://x86.renejeschke.de/html/file_module_x86_id_26.html
    # jmp (eb/e9), http://x86.renejeschke.de/html/file_module_x86_id_147.html
    # jxx (0F 80/0F 81/0F 82/0F 83/0F 84/0F 85/0F 86/0F 87/0F 88/0F 89/0F 8A/0F 8B/0F 8C/0F 8D/0F 8E/0F 8F/70/71/72/73/74/75/76/77/78/79/7A/7B/7C/7D/7E/7F), http://x86.renejeschke.de/html/file_module_x86_id_146.html
    # jcxz/jecxz (67 e3/e3)
    # loop/loope/loopz/loopne/loopnz (e0/e1/e2), http://x86.renejeschke.de/html/file_module_x86_id_161.html
    if buf[idx] == 0xf2:
        idx += 1
        mpx_candidate = True

    if buf[idx] in {0xe0, 0xe1, 0xe2, 0xe3, 0xe8, 0xe9, 0xeb}:
        idx += 1
    elif buf[idx] == 0x0f and (0x80 <= buf[idx + 1] <= 0x8f):
        idx += 2
    elif 0x70 <= buf[idx] <= 0x7f:
        idx += 1
    elif buf[idx] == 0x67 and buf[idx + 1] == 0xe3:
        idx += 2

    if mpx_candidate and idx == 1:
        idx = 0

    if idx:
        return buf[0:idx], buf[idx:]
    else:
        return None, None


def try_add_relative_instruction(ea):
    """
    Identify if the asm code at the given address contains a relative command.
    If it is, add it to the global dict of addresses of relative commands
    :param ea: Address to test
    :return: None
    """
    global g_relative_instructions
    # need operand length, so parse it manually
    instruction_bytes, operand = parse_relative(ea)
    if instruction_bytes and operand:
        assert len(idc.print_operand(ea, 1)) == 0, 'more than 1 operand'
        assert len(operand) == 1 or len(operand) == 4, 'operand is not rel32'
        g_relative_instructions[ea] = [idc.get_operand_value(ea, 0), instruction_bytes.hex(), len(instruction_bytes),
                                       len(instruction_bytes + operand)]
        return True
    return False


def try_add_rip_relative_inst(ea):
    """
    If the instruction at the given address is x64 rip-relative one, adds it to the "rip_relative" dict
    :param ea: Address of instruction to test
    """
    global g_relative_instructions

    buf = idc.get_bytes(ea, idc.get_item_size(ea))
    res = False
    for ins in g_disassembler.disasm(buf, 0):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
                res = True
                g_rip_relative_instructions[ea] = [ins.disp + ea + len(ins.bytes), ba2hex(ins.bytes), ins.disp_size,
                                               len(ins.bytes)]
    return res


def add_basic_block(ea, mnem):
    """
    Identify if the asm code at the given address is the start of a basic block.
    Basic block for us is a conditional jump/call/loop.
    :param ea: Address to test
    :return: None
    """
    global g_basic_blocks
    global g_exec_segments

    # for function head
    if mnem == "":
        g_basic_blocks.append(ea)
        return

    # skip indirect jumps and jumps to data segment
    operand = idc.get_operand_value(ea, 0)
    if operand < 100:
        return
    in_exec_segments = False
    for start, end in g_exec_segments:
        if operand >= start and operand < end:
            in_exec_segments = True
    if not in_exec_segments:
        return
    
    # for jmp, just get one target
    if mnem == "jmp":
        g_basic_blocks.append(operand) # target of jmp
    else:
        # identify as basic block, jxx/loop true/false target
        g_basic_blocks.append(idc.next_head(ea)) # inverse target of jxx
        g_basic_blocks.append(operand) # target of jxx

    return

def set_basic_block_colors():
    """
    Helper function to color the start of every basic block we identified
    :return: None
    """
    global g_basic_blocks
    for ea in g_basic_blocks:
        idc.set_color(ea, idc.CIC_ITEM, BASIC_BLOCK_COLOR)

def identify_seh_handlers():
    """
    This is a best-effort code to identify common default exception handler functions,
    to use later in instrumentation when we patch the exception records for x64 binaries.
    """
    global f_c_handler, f_gs_handler, f_gs_handler_seh
    for func_addr in Functions():
        func_name = idc.get_func_name(func_addr)
        if func_name == '__C_specific_handler_0':
            f_c_handler = func_addr
        elif func_name == '__GSHandlerCheck':
            f_gs_handler = func_addr
        elif func_name == '__GSHandlerCheck_SEH':
            f_gs_handler_seh = func_addr

def calculate_jumptable_size(ea: int, parsed_size: int) -> int:
    """
    Uses a heuristic to calculate the number of cases in a jumptable.
    This is relevant in cases where IDA miscalculates.
    @param ea: Address of the jumptable
    @param parsed_size: The size of the jumptable according to IDA
    @return: The number of cases in a jumptable.
    """
    element_num = parsed_size
    ## Jumptable heuristics
    # Before the switch jump, there's a check that the jump is within bounds
    # For example, a switch-case of 5 cases, will have 'cmp eax, 4; ja label_default'
    # We're searching for that comparison.
    # If the jumptable uses an additional indirect table then we discard our previous check and trust IDA's parsing.
    # TODO Calculate the number of elements more precisely
    inc_up = ('jae', 'jnb', 'jnc')
    inc_down = ('jbe', 'jna')
    non_inc_up = ('ja', 'jnbe')
    non_inc_down = ('jb', 'jnae', 'jc')

    MAX_STEPS_BACK = 10
    prev_insn = idc.prev_head(ea)
    heur_element_num = 0
    found_indirect_table = False
    for i in range(MAX_STEPS_BACK):
        if idc.print_insn_mnem(prev_insn) == 'cmp':
            heur_element_num = idc.get_operand_value(prev_insn, 1) + 1
            break
        # This is indicative of an additional indirect table usage
        elif idc.print_insn_mnem(prev_insn) == 'movzx' and idc.print_operand(prev_insn, 0).endswith('ax'):
            found_indirect_table = True
        prev_insn = idc.prev_head(prev_insn)
    if found_indirect_table == False and heur_element_num > element_num:
        print(f"At {hex(ea)}: Jumptable heuristic was used, parsed size: {element_num}, "
              f"heur size: {heur_element_num} (Found indirect: {found_indirect_table})")
        element_num = heur_element_num
    return element_num

def check_jumptable(ea: int) -> None:
    """
    Jump tables use hardcoded offsets that needs to be adjusted too.
    Fortunately, IDA recognizes and parses them pretty well
    :param ea: The address of the jmp table
    """
    switch_info = idaapi.get_switch_info(ea)
    if not switch_info or switch_info.jumps == 0:
        return

    global g_jmp_tbls, g_basic_blocks
    func_dict = {1: ida_bytes.get_byte, 2: ida_bytes.get_16bit, 4: ida_bytes.get_wide_dword}
    loc = switch_info.jumps
    element_num = calculate_jumptable_size(ea, switch_info.get_jtable_size())
    element_size = switch_info.get_jtable_element_size()
    elbase = switch_info.elbase
    if element_size == 4:
        for num in range(0, element_num):
            table_entry = loc + num * element_size
            if func_dict[element_size](table_entry) == 0:
                print(f"At {hex(ea)}: found empty entry (idx {num})")
                continue
            jmp_target = func_dict[element_size](table_entry) + elbase
            if not g_jmp_tbls.get(jmp_target):
                g_jmp_tbls[jmp_target] = []
            g_jmp_tbls[jmp_target].append((table_entry, element_size, elbase))
            g_basic_blocks.append(jmp_target)

def output_to_file():
    """
    Gather all collected data into a dict and dump it into a json file.
    :return:
    """
    ida_dump = {'bb': g_basic_blocks, 'jmptables': g_jmp_tbls, 'relative': g_relative_instructions, 'rip_relative': g_rip_relative_instructions, 
                'functions': g_funcs, 'c_handler': f_c_handler, 'gs_handler': f_gs_handler,
                'gs_handler_seh': f_gs_handler_seh}
    
    print('[INFO]', str(len(g_basic_blocks)), 'blocks')
    print('[INFO]', str(len(g_relative_instructions)), 'branches')

    with open('C:\\Users\\pwn\\Desktop\\dump.json', 'w+') as f:
        json.dump(ida_dump, f)
    print('[INFO]', 'dump.json is created')


def partial_exclude(start, end=None):
    """
    Exclude functions by offsets from the list of basic blocks we instrument.
    Examples: partial_exclude(ScreenEA()), partial_exclude(0x401020, 0x401040)
    :param start: Functions' start address
    :param end: Functions' end address
    :return: None
    """
    global g_basic_blocks
    if end is None:
        # clear whole function
        start = idc.get_next_func(idc.get_prev_func(start))
        end = idc.find_func_end(start)
    for head in Heads(start, end):
        if head in g_basic_blocks:
            idc.set_color(head, idc.CIC_ITEM, EXPLICITLY_EXCLUDED_COLOR)
            g_basic_blocks.remove(head)


def partial_exclude_by_name(expr):
    """
    Exclude functions by regex from the list of basic blocks we instrument.
    Example: partial_exclude_by_name('(_?Cm|_Hv[^il])')
    :param expr: regex of function names
    :return: None
    """
    global g_basic_blocks
    func_finder = lambda x: re.search(expr, idc.get_func_name(x))
    funcs_to_exclude = set(filter(func_finder, g_basic_blocks))
    for func in funcs_to_exclude:
        idc.set_color(func, idc.CIC_ITEM, EXPLICITLY_EXCLUDED_COLOR)
    g_basic_blocks = list(set(g_basic_blocks) - funcs_to_exclude)


def partial_include_by_name(expr):
    """
    Include only functions that match the given regex in the list of basic blocks we instrument.
    Example: partial_include_by_name('(_?Cm|_Hv[^il])')
    :param expr: regex of function names
    :return: None
    """
    global g_basic_blocks
    func_finder = lambda x: re.search(expr, idc.get_func_name(x))
    funcs_to_include = set(filter(func_finder, g_basic_blocks))
    for func in set(g_basic_blocks) - funcs_to_include:
        idc.set_color(func, idc.CIC_ITEM, EXPLICITLY_INCLUDED_COLOR)
    g_basic_blocks = list(funcs_to_include)


def process_segment(segment_start, segment_end):
    """
    Inspects each command in a segment for relevant things, such as basic blocks and relative commands.
    :param segment_start: Segment start address
    :param segment_end: Segment end address
    :return: None
    """
    global g_func_addrs
    func_start = None

    # This goes through each instruction or data item in the segment
    for head in Heads(segment_start, segment_end):
        if idc.is_code(idc.get_full_flags(head)):
            if not func_start:
                # Start of a function
                func_start = head
                add_basic_block(head, "")

            # If an instruction is relative, it cannot be rip relative. If an instruction is rip relative it cannot be a jump table.
            is_rel = False
            is_rip_rel = False
            mnem = idc.print_insn_mnem(head)

            if mnem.startswith(("call", "j", "loop")):
                add_basic_block(head, mnem)
                is_rel = try_add_relative_instruction(head)
            if not is_rel:
                is_rip_rel = try_add_rip_relative_inst(head)
            if not is_rip_rel:
                check_jumptable(head)
        else:
            if func_start is not None:
                # For MSVC binaries, end of a function contains a single int3 instruction
                g_funcs.update({func_start: head})
                func_start = None

g_exec_segments = []
def process_file():
    """
    The main function of this script. This parses the PE and outputs it to a file.
    :return:
    """
    global g_basic_blocks
    global g_exec_segments

    # Wait for autoanalysis
    idc.auto_wait()
    
    print("[INFO] Rebase image base to 0 before use!")
    
    g_exec_segments = [[x, idc.get_segm_end(x)] for x in Segments() if (idaapi.getseg(x).perm & idaapi.SEGPERM_EXEC)]
    for segment_start, segment_end in g_exec_segments:
        process_segment(segment_start, segment_end)

    g_basic_blocks = sorted(list(set(g_basic_blocks)))
    set_basic_block_colors()
    identify_seh_handlers()

    # dump result
    print('[INFO] To do partial instrumentation use the functions partial_exclude/partial_exclude_by_name/partial_include_by_name')
    print('[INFO] And then call output_to_file() again')
    output_to_file()


if __name__ == '__main__':
    process_file()
