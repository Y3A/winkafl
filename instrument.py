import sys

import engine
import asm_stubs

if (len(sys.argv) < 3):
    print(f"[*] Usage: python {sys.argv[0]} <path to binary> <path to ida data>")
    sys.exit(0)

input("Yes, I have rebased the program to 0 before using ida_dumper.py")
input("Yes, I have updated relevant entrypoint offsets")

orig_binary_path = sys.argv[1]
ida_data_path = sys.argv[2]

inst_binary_path = engine.duplicate_binary(orig_binary_path)

engine.load_binary(inst_binary_path)
engine.load_ida_data(ida_data_path)

engine.try_clear_overlay()
engine.make_new_segments()
engine.inject_into_bb(asm_stubs.asm(asm_stubs.asm_filter))
engine.fix_jumps()
engine.write_bb()

engine.fix_exports()

engine.fix_entrypoint_auto()

engine.fix_exceptions()

engine.fix_cfg()

engine.fix_jumptables()

engine.fix_checksum()
engine.commit_binary()

print(f"[+] Success -> {inst_binary_path}")
