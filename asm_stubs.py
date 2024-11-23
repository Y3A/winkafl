from keystone import Ks, KS_ARCH_X86, KS_MODE_64

'''
cur_location = <COMPILE_TIME_RANDOM>;
shared_mem[cur_location ^ prev_location]++; 
prev_location = cur_location >> 1;

C_ADDR1:    cur_location
C_ADDR2:    cur_location >> 1
M_PREV_LOC: &prev_location
M_AREA_PTR: &shared_mem (will be updated by fuzzer harness)
M_PID:      harness pid (only works for kernel targets)
'''
C_ADDR1 = 0x4444444444444444
C_ADDR2 = 0x5555555555555555
M_PREV_LOC = 0x66666666
M_PID = 0x77777777
M_AREA_PTR = 0x88888888

def asm(code) -> bytearray:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    return bytearray(ks.asm(code)[0])

# Common prefix for our shellcodes, saves our used registers
sc_prefix = '''
push rbx
push rax
pushfq
'''

# Common suffix for our shellcodes, restores our used registers
sc_suffix = '''
popfq
pop rax
pop rbx
'''

# Shellcode that updates for all
# Use this when fuzzing callbacks where a random thread is pre-empted to run/usermode
asm_all = sc_prefix + f'''
mov rax, QWORD PTR [rip+{hex(M_PREV_LOC)}]  # __afl_prev_loc @ .cov+0x10
mov rbx, {hex(C_ADDR1)}
xor rbx, rax
mov rax, QWORD PTR [rip+{hex(M_AREA_PTR)}]  # __afl_area_ptr @ .cov
test rax, rax
jz skip
add rax, rbx                
inc BYTE PTR [rax]              
mov rax, {hex(C_ADDR2)}
mov QWORD PTR [rip+{hex(M_PREV_LOC)}], rax
skip:
''' + sc_suffix

# Shellcode that only updates coverage bitmap if the current pid matches the harness's pid
asm_filter = sc_prefix + f'''
mov rax, QWORD PTR gs:[188h]                 # PsGetCurrentProcessId()
mov rax, QWORD PTR [rax+4C8h]
cmp rax, QWORD PTR [rip+{hex(M_PID)}]        # pid @ .cov+0x20
jne skip
mov rax, QWORD PTR [rip+{hex(M_PREV_LOC)}]   # __afl_prev_loc @ .cov+0x10
mov rbx, {hex(C_ADDR1)}
xor rbx, rax
mov rax, QWORD PTR [rip+{hex(M_AREA_PTR)}]   # __afl_area_ptr @ .cov
test rax, rax
jz skip
add rax, rbx                
inc BYTE PTR [rax]              
mov rax, {hex(C_ADDR2)}
mov QWORD PTR [rip+{hex(M_PREV_LOC)}], rax
skip:
''' + sc_suffix

def get_filter_sc():
    return asm(asm_filter)