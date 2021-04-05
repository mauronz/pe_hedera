from pe_hedera.session import HederaSession, HederaHook

#sample https://app.any.run/tasks/11ae7dcd-0f53-4d9e-979f-277b3b33773e/

def get_dest_from_InternetConnectW(hook, args):
    # second param = pointer to IP string
    # third param  = port
    data = hook.session.read_mem(args[1], 0x40)
    # extact the wchar string
    tmp = data.split(b"\x00\x00\x00")[0] + b"\x00"
    ip = tmp.decode("utf-16le")
    print("{}:{:d}".format(ip, args[2]))
    # override the first param with NULL
    # to make InternetConnectW fail instantly
    args[0] = 0

session = HederaSession(["emotet.exe"])
session.initialize()
hook = HederaHook(session,
                  dll_name="wininet.dll",
                  function="InternetConnectW",
                  param_num=8,
                  before_hook=get_dest_from_InternetConnectW,
                  override_params=True)
hook.set()
session.start()