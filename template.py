from pwn import *
from argparse import ArgumentParser
from pathlib import Path
from typing import Callable, Any

# ------- Config -------
LOG_LEVEL = 'debug'
OS = 'linux'
ARCH = 'amd64'
TERMINAL = ['wt.exe', 'bash', '-c']

ATTACHMENT = './pwn'
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
args = parser.parse_args()

if args.host and args.port:
    REMOTE = True
    HOST = args.host
    PORT = int(args.port)

if args.remote:
    REMOTE = True
    HOST, PORT = args.remote.split(':')
    PORT = int(PORT)

# To avoid error
if not Path(args.ATTACHMENT).exists():
    ATTACHMENT = '/bin/sh'
    DEBUG = False
else:
    ATTACHMENT = args.ATTACHMENT

if not Path(args.libc).exists():
    LIBC = '/bin/sh'
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

if REMOTE:
    DEBUG = False
    sh = remote(HOST, PORT)
elif GDB:
    sh = gdb.debug([ATTACHMENT], gdbscript=GDB_SCRIPT)
else:
    sh = process([ATTACHMENT])

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
p4: Callable[[int, Any], bytes] = lambda number, **kwargs: pack(number, **kwargs)
p8: Callable[[int, Any], bytes] = lambda number, **kwargs: pack(number, **kwargs)
p16: Callable[[int, Any], bytes] = lambda number, **kwargs: pack(number, **kwargs)
p32: Callable[[int, Any], bytes] = lambda number, **kwargs: pack(number, **kwargs)
p64: Callable[[int, Any], bytes] = lambda number, **kwargs: pack(number, **kwargs)
u4: Callable[[bytes, Any], int] = lambda number, **kwargs: unpack(number, **kwargs)
u8: Callable[[bytes, Any], int] = lambda number, **kwargs: unpack(number, **kwargs)
u16: Callable[[bytes, Any], int] = lambda number, **kwargs: unpack(number, **kwargs)
u32: Callable[[bytes, Any], int] = lambda number, **kwargs: unpack(number, **kwargs)
u64: Callable[[bytes, Any], int] = lambda number, **kwargs: unpack(number, **kwargs)


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
