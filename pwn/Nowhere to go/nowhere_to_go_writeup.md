# Nowhere to go

**Category:** Pwn | **Difficulty:** Hard | 

## Overview
A tiny statically-linked binary served via QEMU VM with a clear buffer overflow but no useful ROP gadgets in the binary itself.

## Solution

The binary has just 4 functions: `read`, `write`, `readwrite`, and `_start`. The `readwrite` function reads 0x80 bytes into a 0x20 buffer — a 0x60 byte overflow. It also echoes 0x80 bytes back, leaking stack pointers.

The challenge is that the binary has **zero useful gadgets** for controlling registers like rdi, rsi, rdx, or rax. The key insight is **ret2vdso**: the Linux kernel maps a vDSO (Virtual Dynamic Shared Object) into every process, and it contains enough gadgets.

**Step 1: Stack Leak**  
Send 0x20 bytes, receive 0x80 echo. Parse stack pointer at offset 0x30.

**Step 2: Write `/bin/sh` to known address**  
Use READ_FUNC gadget to write `/bin/sh\0` to the page-aligned stack base.

**Step 3: Dump stack to find vDSO base**  
Use WRITE_FUNC to dump the entire stack (0x21000 bytes). Search for AT_SYSINFO_EHDR (auxv type 0x21) which contains the vDSO base address.

**Step 4: Dump vDSO**  
Use WRITE_FUNC to dump 0x2000 bytes from the vDSO base. Search for gadgets.

**Step 5: ROP to shell**  
Remote vDSO gadgets found:
- `pop rdx; pop rax; ret` at +0xba0
- `pop rbx; pop r12; pop rbp; ret` at +0x8c6
- `mov rdi, rbx; mov rsi, r12; syscall` at +0x8e3

Chain: set rdx=0, rax=59 (execve), rbx=&"/bin/sh", r12=0 (NULL argv), then `mov rdi,rbx; mov rsi,r12; syscall` → `execve("/bin/sh", NULL, NULL)`.

Run `cat /*.txt` to get the flag (filename is randomized at boot).

See `solve.py` for the full exploit.

## Key Takeaways
- **ret2vdso**: When a binary lacks gadgets, the vDSO mapped by the kernel provides them.
- The vDSO is kernel-specific — different kernels have different vDSO contents and gadget offsets.
- Dump the remote vDSO by leaking its address from the auxv (AT_SYSINFO_EHDR) on the stack.
- The `write` function in the binary can be used as an arbitrary memory dump primitive via ROP.
