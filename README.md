# winkafl

- Based on the original [pe-afl](https://github.com/wmliang/pe-afl) by [wmliang](https://x.com/_wmliang_) and [peafl64](https://github.com/Sentinel-One/peafl64) by [SentinelOne](https://www.sentinelone.com/)
- Supports fuzzing 64-bit drivers on Windows 11
- Blogpost at https://y3a.github.io/2023/12/22/fuzzing6/

# Usage

1.  Use `ida_dumper.py` in IDA to generate basic block information
2. Use `instrument.py` to statically instrument target driver
3. Replace target driver in fuzzing VM with instrumented version
4. Compile `helper` driver and load in fuzzing VM
5. Attach WinDbg to fuzzing VM
6. Fuzz and wait for crash
7. Use `post_crash/dump_sample.py` to extract crashing sample

# FAQ

**Q: Why does my winafl return `[-] PROGRAM ABORT : No instrumentation detected`**?

**A:** This is likely due to the offsets changing across Windows versions.
Modify the pid filtering shellcode in `asm_stubs.py` to match the implementation of `PsGetCurrentProcessId()` on your machine.
The current offset is for Windows 11 23H2.
