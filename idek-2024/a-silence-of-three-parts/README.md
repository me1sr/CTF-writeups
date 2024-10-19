The intended 8 bit bruteforce exploit
basically use the vuln to hijack the tcache_perthread_struct (requires 8 bit bruteforce)
then attack arena->top with 1 byte partial overwrites to pivot the top in the libc and use that to get a leak (and a shell) with stdout

and also the 12 bit exploit, same technique used in https://github.com/5kuuk/CTF-writeups/tree/main/tfc-2024/mcguava

(todo: make a real writeup)

I did not flag this challenge during the ctf but I still made an exploit because the intended exploit technique is very interesting, thank you unvariant for this challenge