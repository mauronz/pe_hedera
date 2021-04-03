import struct
import time
import win32file
import win32pipe
import pywintypes
import threading
import subprocess
import os

EXE_PATH = os.path.join(os.path.dirname(__file__), "pe_hedera.exe")

PIPE_NAME = r'\\.\pipe\hederacmdpipe'
HOOK_PIPE_NAME = r'\\.\pipe\hederahookpipe'
PIPE_BUFFER_SIZE = 65535

CODE_ERROR=0x2000
CODE_OK=0x2001
CODE_INJECT=0x2002
CODE_THREAD=0x2003
CODE_INIT=0x2004
CODE_HOOK_DATA=0x2005

CODE_START=0x4000
CODE_SET_HOOK_NAME=0x4001
CODE_SET_HOOK_ADDR=0x4002
CODE_REMOVE_HOOK=0x4003
CODE_READ_MEM=0x4004
CODE_WRITE_MEM=0x4005
CODE_STOP=0x4006

HT_BEFORE=0
HT_AFTER=1

CV_STDCALL=0
CV_CDECL=1

'''
These functions are used inside the native components of the hooks,
so any hook set on them must have do_call=True
'''
special_functions = [
    ("kernel32.dll", "ReadFile"),
    ("kernel32.dll", "WriteFile"),
    ("kernel32.dll", "GetLastError"),
    ("kernel32.dll", "HeapAlloc"),
    ("kernel32.dll", "HeapFree"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "GetModuleHandleExA"),
    ("kernel32.dl", "ResumeThread"),
    ("ntdll.dll", "RtlAllocateHeap"),
    ("ntdll.dll", "RtlFreeHeap"),
    ("ntdll.dll", "NtResumeThread")
]

class HederaMessage:
    def receive(pipe):
        ret, data = win32file.ReadFile(pipe, 4, None)
        if len(data) != 4:
            return None
        msg_size = struct.unpack("<I", data)[0]
        ret, data = win32file.ReadFile(pipe, msg_size, None)
        if len(data) != msg_size:
            return None
        code = struct.unpack("<I", data[:4])[0]
        arg_count = struct.unpack("<I", data[4:8])[0]
        args = list()
        off = 8
        for i in range(arg_count):
            arg_size = struct.unpack("<I", data[off:off+4])[0]
            off += 4
            args.append(data[off:off+arg_size])
            off += arg_size
        return HederaMessage(code, pipe, args)

    def __init__(self, code, pipe, args=None):
        self.code = code
        if pipe == None:
            self.pipe = cmd_pipe
        else:
            self.pipe = pipe
        if args == None:
            args = list()
        self.args = args

    def send(self):
        serialized = struct.pack("<I", self.code) + struct.pack("<I", len(self.args))
        for arg in self.args:
            sarg = None
            if type(arg) == int or type(arg) == bool:
                sarg = struct.pack("<I", arg)
            elif type(arg) == str:
                sarg = arg.encode() + b"\x00"
            else:
                sarg = arg

            serialized += struct.pack("<I", len(sarg))
            serialized += sarg
        win32file.WriteFile(self.pipe, struct.pack("<I", len(serialized)) + serialized)

    def __str__(self):
        return '''code: {:x}
argcount: {}'''.format(self.code, len(self.args))


class HederaHook:
    current_id = 0
    active_hooks = dict()

    def __init__(self, session, dll_name=None, function=None, address=-1, param_num=0, call_conv=CV_STDCALL, before_hook=None, after_hook=None, do_call=True, override_ret=False, override_params=False):
        self.session = session
        self.dll_name = dll_name
        self.function = function
        self.address = address
        self.param_num = param_num
        self.call_conv = call_conv
        self.before_hook = before_hook
        self.after_hook = after_hook
        self.do_call = do_call
        self.override_ret = override_ret
        self.override_params = override_params
        self.id = HederaHook.current_id
        HederaHook.current_id += 1

    def set(self):
        if not self.do_call and (self.dll_name, self.function) in special_functions:
            print("[-] Error: native code of hooks requires {:}.{:}, a hook on it must have do_call=True".format(self.dll_name, self.function))
            return False

        has_bhook = self.before_hook is not None
        has_ahook = self.after_hook is not None

        if self.dll_name and self.function:
            code = CODE_SET_HOOK_NAME
            args = [self.id, self.dll_name, self.function]
        elif self.address > -1:
            code = CODE_SET_HOOK_ADDR
            args = [self.id, self.address]
        else:
            print("[-] Error: hook definition must have valid dll and function names or a valid address")
            return False

        args.extend([self.param_num, self.call_conv, has_bhook, has_ahook, self.do_call, self.override_ret, self.override_params])

        msg = HederaMessage(code, self.session.cmd_pipe, args)
        msg.send()
        resp = HederaMessage.receive(self.session.cmd_pipe)
        if (resp.code) == CODE_OK:
            HederaHook.active_hooks[self.id] = self
            return True
        return False

    def remove(self):
        msg = HederaMessage(CODE_REMOVE_HOOK, self.session.cmd_pipe, [self.dll_name, self.function])
        msg.send()
        resp = HederaMessage.receive(self.session.cmd_pipe)
        if (resp.code) == CODE_OK:
            HederaHook.active_hooks.pop(self.id)
            return True
        return False

    def __str__(self):
        if self.dll_name and self.function:
            return "{:}.{:}".format(self.dll_name, self.function)
        elif self.address > -1:
            return "0x{:x}".format(self.address)
        else:
            return "INVALID_HOOK"


class HederaSession:

    def handle_data(session):
        try:
            win32pipe.ConnectNamedPipe(session.hook_pipe, None)
            while True:
                msg = HederaMessage.receive(session.hook_pipe)
                if msg.code == CODE_HOOK_DATA:
                    hook_id = struct.unpack("<I", msg.args[0])[0]
                    hook_type = struct.unpack("<I", msg.args[1])[0]
                    params = list()
                    for arg in msg.args[2:]:
                        dword_arg = struct.unpack("<I", arg)[0]
                        params.append(dword_arg)
                    hook = HederaHook.active_hooks[hook_id]
                    if hook_type == HT_BEFORE:
                        hook.before_hook(hook, params)
                        if hook.override_params:
                            resp_args = params
                        else:
                            resp_args = None
                    elif hook_type == HT_AFTER:
                        retvalue = params.pop()
                        new_retvalue = hook.after_hook(hook, params, retvalue)
                        if new_retvalue is None:
                            new_retvalue = 0
                        resp_args = [new_retvalue]
                    if not session.is_alive:
                        break
                    resp = HederaMessage(CODE_OK, session.hook_pipe, resp_args)
                elif msg.code == CODE_INJECT:
                    process_pid = struct.unpack("<I", msg.args[0])[0]
                    process_tid = struct.unpack("<I", msg.args[1])[0]
                    process_path = msg.args[2].decode("utf-16le")
                    if session.switch_hook:
                        session.switch_hook(process_path, process_pid, process_tid)
                    print("New process: {:} (pid {:d})")
                    if session.auto_switch:
                        resp_code = CODE_OK
                    else:
                        print("Switch to it? (y/n): ".format(process_path, process_pid), end="")
                        ans = input()
                        if ans == "y":
                            resp_code = CODE_OK
                        else:
                            resp_code = CODE_ERROR
                    resp = HederaMessage(resp_code, session.hook_pipe)
                elif msg.code == CODE_INIT:
                    for hook in HederaHook.active_hooks.values():
                        hook.set()
                    resp = HederaMessage(CODE_OK, session.hook_pipe)
                else:
                    resp = HederaMessage(CODE_ERROR, session.hook_pipe)
                resp.send()
        except pywintypes.error as e:
            print("handle_data exception:", e)


    def __init__(self, cmdline, auto_switch=False, switch_hook=None):
        self.cmdline = cmdline
        self.cmd_pipe = None
        self.hook_pipe = None
        self.is_alive = True
        self.auto_switch = auto_switch
        self.switch_hook = switch_hook


    def read_mem(self, addr, size):
        msg = HederaMessage(CODE_READ_MEM, self.cmd_pipe, [addr, size])
        msg.send()
        resp = HederaMessage.receive(self.cmd_pipe)
        if resp.code == CODE_OK:
            return resp.args[0]

    def write_mem(self, addr, data):
        msg = HederaMessage(CODE_WRITE_MEM, self.cmd_pipe, [addr, data])
        msg.send()
        resp = HederaMessage.receive(self.cmd_pipe)
        return resp.code == CODE_OK


    def initialize(self):
        try:
            self.cmd_pipe = win32pipe.CreateNamedPipe(PIPE_NAME,
                                                   win32pipe.PIPE_ACCESS_DUPLEX,
                                                   win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT | win32pipe.PIPE_READMODE_MESSAGE,
                                                   win32pipe.PIPE_UNLIMITED_INSTANCES,
                                                   PIPE_BUFFER_SIZE,
                                                   PIPE_BUFFER_SIZE, 0, None)

            self.hook_pipe = win32pipe.CreateNamedPipe(HOOK_PIPE_NAME,
                                                   win32pipe.PIPE_ACCESS_DUPLEX,
                                                   win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT | win32pipe.PIPE_READMODE_MESSAGE,
                                                   win32pipe.PIPE_UNLIMITED_INSTANCES,
                                                   PIPE_BUFFER_SIZE,
                                                   PIPE_BUFFER_SIZE, 0, None)
        except pywintypes.error as e:
            print("exception:", e)

        hook_data_thread = threading.Thread(target=HederaSession.handle_data, args=(self,))
        hook_data_thread.start()

        args = [EXE_PATH, "/pipe", PIPE_NAME]
        args.extend(self.cmdline)
        subprocess.Popen(args)

        try:
            win32pipe.ConnectNamedPipe(self.cmd_pipe, None)
            msg = HederaMessage(CODE_INIT, self.cmd_pipe, [HOOK_PIPE_NAME])
            msg.send()
            resp = HederaMessage.receive(self.cmd_pipe)
            if resp.code == CODE_OK:
                self.image_base = struct.unpack("<I", resp.args[0])[0]
                print("Image base: 0x{:x}".format(self.image_base))
        except pywintypes.error as e:
            print("exception:", e)

    def start(self):
        msg = HederaMessage(CODE_START, self.cmd_pipe)
        msg.send()
        resp = HederaMessage.receive(self.cmd_pipe)

    def stop(self):
        self.is_alive = False
        self.hook_pipe.Close()
        msg = HederaMessage(CODE_STOP, self.cmd_pipe)
        msg.send()
        resp = HederaMessage.receive(self.cmd_pipe)
        if resp:
            self.cmd_pipe.Close()