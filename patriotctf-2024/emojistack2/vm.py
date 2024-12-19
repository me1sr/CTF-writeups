from PIL import Image

initial_state = Image.open("./initial_state.png").convert("L")

with open("./program.txt", "r") as f:
    code = f.read()

ip = 0
sp_x = 0
sp_y = 0
stack = [[0]*255 for _ in range(255)]

for y in range(255):
    for x in range(255):
        stack[y][x] = initial_state.getpixel((x, y))

def decode_clock(input):
    match input:
        case "🕛":
            return 0
        case "🕐":
            return 1
        case "🕑":
            return 2
        case "🕒":
            return 3
        case "🕓":
            return 4
        case "🕔":
            return 5
        case "🕕":
            return 6
        case "🕖":
            return 7
        case "🕗":
            return 8
        case "🕘":
            return 9
        case "🕙":
            return 10
        case "🕚":
            return 11

def execute(i, depth=0):
    global ip, sp_x, sp_y, stack, code
    match code[i]:
        case "👉":
            sp_x += 1
        case "👈":
            sp_x -= 1
        case "👆":
            sp_y += 1
        case "👇":
            sp_y -= 1
        case "👍":
            stack[sp_y][sp_x] += 1
            stack[sp_y][sp_x] &= 0xff
        case "👎":
            stack[sp_y][sp_x] -= 1
            stack[sp_y][sp_x] &= 0xff
        case "💬":
            print(chr(stack[sp_y][sp_x]), end="")
        case "👂":
            stack[sp_y][sp_x] = ord(input()[0])
        case "🫸":
            if stack[sp_y][sp_x] == 0:
                opening = 0
                j = i+1
                while True:
                    if code[j] == "🫸":
                        opening += 1
                    elif code[j] == "🫷" and opening == 0:
                        break
                    j += 1
                ip = j + 1
        case "🫷":
            if stack[sp_y][sp_x] != 0:
                closing = 0
                j = i-1
                while True:
                    if code[j] == "🫷":
                        closing += 1
                    elif code[j] == "🫸" and closing == 0:
                        break
                    j -= 1
                ip = j + 1
        case "🔁":
            num = decode_clock(code[i+1])*144 + decode_clock(code[i+2])*12 + decode_clock(code[i+3])
            for _ in range(num):
                execute(i-1, depth+1)
            if depth == 0:
                ip += 3


try:
    k = 0
    while ip < len(code):
        # print(k, "sp: (%#x, %#x), ip: %#x" % (sp_x, sp_y, ip), code[ip:ip+4])
        execute(ip)
        ip += 1
        k += 1
except KeyboardInterrupt:
    pass
except:
    print("sp: (%#x, %#x)\nip: %#x" % (sp_x, sp_y, ip))

input()
print(hex(stack[y][x]))

img = Image.new("L", (255, 255))
for y in range(255):
    for x in range(255):
        # print(hex(stack[y][x]))
        img.putpixel((x, y), stack[y][x])
img.convert("L").show()