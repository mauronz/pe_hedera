import string

def parse_int(s, args):
    if s[0] == "$":
        param_index = int(s[1:])
        if param_index >= len(args):
            print("Param out of range")
            return None
        else:
            return args[param_index]
    if s[:2] == "0x":
        return int(s, 16)
    return int(s)

def print_hexdump(data):
    printable = string.printable.encode()
    whitespace = string.whitespace.encode()

    lines = len(data) // 16
    if len(data) % 16:
        lines += 1
    for i in range(lines):
        end = min(len(data), (i + 1) * 16)
        hex_str = " ".join("{:02X}".format(x) for x in data[i*16:end])
        char_str = ""
        for x in data[i*16:end]:
            if x in printable and x not in whitespace:
                char_str += chr(x)
            else:
                char_str += "."
        padding = (16 * 3 - 1 - len(hex_str)) * " "
        print("{:}{:} | {:}".format(hex_str, padding, char_str))

def handle_readmem(hook, cmd_args, hook_params):
    addr = parse_int(cmd_args[1], hook_params)
    size = parse_int(cmd_args[2], hook_params)
    data = hook.session.read_mem(addr, size)
    if data:
        print_hexdump(data)

def handle_writemem(hook, cmd_args, hook_params):
    addr = parse_int(cmd_args[1], hook_params)
    if cmd_args[2][0] == "\"":
        data = cmd_args[2][1:-1].encode() + b"\x00"
    else:
        try:
            data = bytes.fromhex(cmd_args[2])
        except ValueError:
            print("Parameter error")
            data = None
    if data and hook.session.write_mem(addr, data):
        print("OK")

def handle_setparam(hook, cmd_args, hook_params):
    try:
        if hook.override_params:
            if cmd_args[1][0] == "$":
                param_index = int(cmd_args[1][1:])
                hook_params[param_index] = parse_int(cmd_args[2], hook_params)
            else:
                print("First argument must be a parameter id (e.g. $0)")
        else:
            print("override_params is false for this hook")
    except ValueError:
        print("Parameter error")

def handle_help(hook, cmd_args, hook_params):
    print("""Accepted command argument formats:
 - base 10 integer, e.g. 1234
 - base 16 integer with 0x, e.g. 0xdeadbeef
 - param id with $ followed by param number, e.g. $0

Available commands:
 - readmem <address> <size>: read memory from the target process and print its hexdump
 - writemem <address> <data>: write data in the memory of the target process,
                              <data> has the following formats
                              - string between double-quotes (null byte is automatically appended)
                              - hex rappresentation, e.g. 13f860bd for the buffer \\x13\\xf8\\x60\\xbd
 - setparam $param_num <value>: ovverride the value of a parmeter (only if override_params is true)
 - continue: resume execution
 - stop: terminate the target process and exit""")


cmd_handlers = {
    "readmem" : (handle_readmem, 3),
    "writemem" : (handle_writemem, 3),
    "setparam" : (handle_setparam, 3),
    "help" : (handle_help, 1)
}

def interactive(hook, params, retvalue=None):
    if retvalue:
        hook_type = "after"
    else:
        hook_type = "before"
    print("\nInteractive mode for hook {:}.{:}\n".format(hook, hook_type))
    print("Params:")
    for i in range(len(params)):
        print(" {:d} - 0x{:x}".format(i, params[i]))
    while True:
        print("\n> ", end="")
        _input = input()
        if len(_input) == 0:
            continue
        split = _input.split(" ")
        split = list(filter(lambda x:len(x)>0, split))
        cmd = split[0].lower()
        if cmd == "continue":
            break
        elif cmd == "stop":
            hook.session.stop()
            break
        elif cmd in cmd_handlers:
            handler, arg_count = cmd_handlers[cmd]
            if len(split) == arg_count:
                handler(hook, split, params)
            else:
                print("{:} requires {:d} arguments".format(cmd, arg_count - 1))
        else:
            print("Unknown command")