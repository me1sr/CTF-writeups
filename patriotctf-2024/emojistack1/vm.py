

with open("input.txt", "r") as f:
    code = f.read()


ip = 0
sp = 0
stack = [0]*0x1000

def execute(i, depth=0):
    global ip, sp, stack, code
    match code[i]:
        case "👉":
            sp += 1
        case "👈":
            sp -= 1
        case "👍":
            stack[sp] += 1
        case "👎":
            stack[sp] -= 1
        case "💬":
            print(chr(stack[sp]), end="")
        case "🔁":
            for _ in range(int(code[i+1:i+3], 16)):
                execute(i-1, depth+1)
            if depth == 0:
                ip += 2

while ip < len(code):
    execute(ip)
    ip += 1
