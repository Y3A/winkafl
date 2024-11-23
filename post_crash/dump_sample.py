import sys
from pykd import dbgCommand

'''
Usage:

.load pykd
!py "C:\\Users\\User\\Desktop\\hacking\\win-kernel\\kernel_instrumentation-main\\post_crash\\dump_sample.py harness.exe 15 C:\\Users\\User\\Desktop\\out.dumpfile"

'''

harness_process_name = sys.argv[1]
max_sample_size = int(sys.argv[2])
output_file = sys.argv[3]
pages_to_map = max_sample_size // 0x1000

res = dbgCommand(f"!process 0 0 {harness_process_name}")
process_base = res.split("\n")[0].split(" ")[1]
dbgCommand(f".process /p {process_base}")
vad_output = dbgCommand("!vad").split("\n")
for line in vad_output:
    if "Pagefile" in line and "READWRITE" in line:
        line_info = line.split()
        start = int(line_info[2], 16)
        end = int(line_info[3], 16)

        if (start - end) != pages_to_map:
            continue

        # Found possible page
        possible_start = start * 0x1000
        possible_sample_size = int(dbgCommand(f"dd {hex(possible_start)} L1").split()[1], 16)

        if possible_sample_size == 0 or possible_sample_size > max_sample_size:
            continue

        # Found target page
        print("Found target page: " + hex(possible_start))
        dbgCommand(f".writemem {output_file} {hex(possible_start+4)} L{hex(possible_sample_size)}")
        print("success")
        sys.exit(0)

print("not found, search manually")
