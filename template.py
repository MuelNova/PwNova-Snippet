from pwn import *
from argparse import ArgumentParser
from pathlib import Path
from typing import Optional, Any, Literal

# ------- Config -------
LOG_LEVEL = 'info'
OS = 'linux'
ARCH = 'amd64'
TERMINAL = ['wt.exe', 'bash', '-c']

ATTACHMENT = './pwn'
RUNARGS = ''
LIBC = './libc.so.6'
HOST = ''
PORT = 0

DEBUG = True
REMOTE = False
GDB = False  # gdb.debug(elf.path, gdbscript=gdbscript)
GDB_SCRIPT = ''

# ------- Config -------
parser = ArgumentParser(description="Pwnable Commandline")
parser.add_argument('ATTACHMENT', nargs='?', default=ATTACHMENT)
parser.add_argument('--libc', '-l', nargs='?', default=LIBC)
parser.add_argument('--no-debug', '-D', action='store_true', default=False, help='Disable debug mode')
parser.add_argument('--remote', '-r', action='store', default="")
parser.add_argument('--host', '-H', action='store', default='')
parser.add_argument('--port', '-p', action='store', default=0)
parser.add_argument('--gdb', '-g', action='store_true', default=GDB, help='Run binary using gdb.debug')
parser.add_argument('--gdb-script', '-G', action='store', default=GDB_SCRIPT)
parser.add_argument('--args', '-a', action='store', default=RUNARGS)
args = parser.parse_args()

if args.host and args.port:
    DEBUG = False
    REMOTE = True
    HOST = args.host
    PORT = int(args.port)

if args.remote:
    DEBUG = False
    REMOTE = True
    HOST, PORT = args.remote.split(':')
    PORT = int(PORT)

if args.args:
    RUNARGS = args.args

# To avoid error
if not Path(args.ATTACHMENT).exists():
    ATTACHMENT = '/bin/sh'
    DEBUG = False
else:
    ATTACHMENT = args.ATTACHMENT

if not Path(args.libc).exists():
    LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
else:
    LIBC = args.libc

if args.no_debug:
    DEBUG = False

if args.gdb:
    DEBUG = False
    GDB=True
    GDB_SCRIPT = args.gdb_script

del parser, ArgumentParser, Path, args

context.log_level = LOG_LEVEL
context.terminal = TERMINAL
context.os = OS
context.arch = ARCH

def get_sh():
    if REMOTE:
        sh_ = remote(HOST, PORT)
    elif GDB:
        sh_ = gdb.debug([ATTACHMENT, *RUNARGS.split(' ')], gdbscript=GDB_SCRIPT)
    else:
        sh_ = process([ATTACHMENT, *RUNARGS.split(' ')])
    return sh_

sh = get_sh()
libc = ELF(LIBC)
elf = ELF(ATTACHMENT)

sendline = sh.sendline
sendlineafter = sh.sendlineafter
send = sh.send
sendafter = sh.sendafter
recv = sh.recv
recvline = sh.recvline
recvuntil = sh.recvuntil
interactive = sh.interactive

# Type Hint
def p4(x: int, endianness: Optional[Literal['little', 'big']] = None, sign = Optional[bool], **kwargs: Any) -> bytes: return pack(x, 4, endianness, sign, **kwargs)
def p8(x: int, endianness: Optional[Literal['little', 'big']] = None, sign = Optional[bool], **kwargs: Any) -> bytes: return pack(x, 8, endianness, sign, **kwargs)
def p16(x: int, endianness: Optional[Literal['little', 'big']] = None, sign = Optional[bool], **kwargs: Any) -> bytes: return pack(x, 16, endianness, sign, **kwargs)
def p32(x: int, endianness: Optional[Literal['little', 'big']] = None, sign = Optional[bool], **kwargs: Any) -> bytes: return pack(x, 32, endianness, sign, **kwargs)
def p64(x: int, endianness: Optional[Literal['little', 'big']] = None, sign = Optional[bool], **kwargs: Any) -> bytes: return pack(x, 64, endianness, sign, **kwargs)
def u4(x: bytes, **kwargs: Any) -> int: return unpack(x, 4, **kwargs)
def u8(x: bytes, **kwargs: Any) -> int: return unpack(x, 8, **kwargs)
def u16(x: bytes, **kwargs: Any) -> int: return unpack(x, 16, **kwargs)
def u32(x: bytes, **kwargs: Any) -> int: return unpack(x, 32, **kwargs)
def u64(x: bytes, **kwargs: Any) -> int: return unpack(x, 64, **kwargs)


def dbg(script: str = '', pause_time: int = 3, **kwargs):
    if DEBUG:
        gdb.attach(sh, script, **kwargs)
        if pause_time == 0:
            pause()
        else:
            pause(pause_time)

class Offset:
    def __init__(self, base: int, program: ELF):
        self.base = base
        self.program = program

    def __getattr__(self, item) -> int:
        """
        offset.plt.puts
        offset.got.puts
        offset.main
        """
        if item in ['plt', 'got']:
            class _:
                def __getattr__(s, i):
                    return self.base + getattr(self.program, item)[i]
            return _()
        return self.base + self.program.symbols[item]

    def __getitem__(self, item) -> int:
        """
        offset['plt', 'puts']
        offset['got', 'puts']
        offset['main']
        """
        if isinstance(item, tuple):
            return self.base + getattr(self.program, item[0])[item[1]]
        else:
            return self.base + self.program.sym[item]

# ------- Exploit -------'
