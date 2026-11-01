import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
SYS_create, SYS_add, SYS_restrict = 444, 445, 446
class Attr(ctypes.Structure): _fields_=[("fs",ctypes.c_uint64),("net",ctypes.c_uint64),("scoped",ctypes.c_uint64)]
class Beneath(ctypes.Structure): _pack_=1; _fields_=[("allowed",ctypes.c_uint64),("fd",ctypes.c_int32)]
abi = libc.syscall(SYS_create, None, 0, 1)
FS_ALL = (1<<16)-1 if abi>=5 else (1<<15)-1   # ABI5: 16 rights incl IOCTL_DEV
READ = (1<<0)|(1<<2)|(1<<3)  # EXECUTE, READ_FILE, READ_DIR
attr = Attr(FS_ALL, (1<<0)|(1<<1) if abi>=4 else 0, 3 if abi>=6 else 0)
size = ctypes.sizeof(Attr) if abi>=6 else (16 if abi>=4 else 8)
rs = libc.syscall(SYS_create, ctypes.byref(attr), size, 0)
assert rs>=0, os.strerror(ctypes.get_errno())
def allow(path, rights):
    fd = os.open(path, os.O_PATH)
    b = Beneath(rights & FS_ALL, fd)
    assert libc.syscall(SYS_add, rs, 1, ctypes.byref(b), 0)==0, (path, os.strerror(ctypes.get_errno()))
    os.close(fd)
for p in ["/usr", "/lib", "/lib64", "/etc", "/proc/self"]:
    if os.path.exists(p): allow(p, READ)
for p in sys.argv[1].split(","): allow(p, (1<<2) if os.path.isfile(p) else READ)
allow("/dev/null", (1<<1)|(1<<2))
libc.prctl(38,1,0,0,0)  # PR_SET_NO_NEW_PRIVS
assert libc.syscall(SYS_restrict, rs, 0)==0, os.strerror(ctypes.get_errno())
os.execvp(sys.argv[2], sys.argv[2:])
