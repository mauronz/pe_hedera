# pe_hedera

pe_hedera is a Python 3 library that allows to execute a Windows executable and define Python hooks which are executed before and/or after function calls.

## Session
A session represents the context of execution of the target process. To set up a session,  create a object **HederaSession** with the target command line as argument:

```python
session = HederaSession(["notepad.exe", "test.txt"])
```

At this point the process is already created, but it is suspended. In order to start the execution, simply call

```python
session.start()
```

Session objects have the attribute `image_base`, the address at which the image of the executable is loaded in the target process. This is useful to set address-based hooks when ASLR is enabled.

### Actions

Through a session object we can perform the following actions:

- session.read_mem(addr, size)
- session.write_mem(addr, data)
- session.stop()

### Process switching

When the target process creates a new process, the library asks whether to switch to it, applying there the current hooks.
Additionally, the constructor of HederaSession accepts the parameter `auto_switch`. If set to True, the library performs the switch without asking for user confermation.

## Hook definitions
Once the session is ready, add the desired hooks.
There are two ways to define a hook, either by symbol name (DLL name + function name), or by address.
Each hook accepts a handler that is executed before the target function (**before-hook**) and one that is executed after it (**after-hook**). 

```python
name_hook = HederaHook(session, 
                       dll_name="kernel32.dll",
                       function="CreateFileA",
                       param_num=7,
                       before_hook=my_before_hook,
                       after_hook=my_after_hook)
                       
address_hook = HederaHook(session, 
                          address=session.image_base+0x1090
                          param_num=3,
                          before_hook=my_before_hook,
                          after_hook=my_after_hook)               
```

*Before-hooks* must have the following prototype:

```python
def my_before_hook(hook, params):
    ...
```

`hook` is a reference to the corresponding HederaHook, while `params` is the list of parameters of the current call (as DWORDs).

The prototype for *after-hooks* is similar:

```python
def my_after_hook(hook, params, retvalue):
    ...
```

It has an additional argument `retvalue`, the return value of the hooked function.

After the hook is created, activate it with

```python
hook.set()
```

### Additional configurations

HederaHook objects accept the following optional parameters:

- `call_conv`: the calling convention of the hooked function, can be either `pe_hedera.session.CV_STDCALL` (default) or `pe_hedera.session.CV_CDECL`
- `do_call`: if False prevent the execution of the hooked function (default True)
- `override_ret`: if True the return value of the after-hook overwrites the one of the hooked function (default False)
- `override_params`: if True, any modification of the params argument of the before-hook is applied to the hooked function (default True)

## Interactive handler

`handlers.interactive` in alternative to the definition of custom before- or after-hooks. It works as a simplified version of a command-line debugger.

```
Accepted command argument formats:
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
 - stop: terminate the target process and exit
```


