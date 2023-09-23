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
parser.add_argument('--debug', '-D', action='store_true', default=DEBUG)
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
p4: Callable[[int, Any], bytes] = lambda number, **kwargs: p4(number, **kwargs)
p8: Callable[[int, Any], bytes] = lambda number, **kwargs: p8(number, **kwargs)
p16: Callable[[int, Any], bytes] = lambda number, **kwargs: p16(number, **kwargs)
p32: Callable[[int, Any], bytes] = lambda number, **kwargs: p32(number, **kwargs)
p64: Callable[[int, Any], bytes] = lambda number, **kwargs: p64(number, **kwargs)
u4: Callable[[bytes, Any], int] = lambda number, **kwargs: u4(number, **kwargs)
u8: Callable[[bytes, Any], int] = lambda number, **kwargs: u8(number, **kwargs)
u16: Callable[[bytes, Any], int] = lambda number, **kwargs: u16(number, **kwargs)
u32: Callable[[bytes, Any], int] = lambda number, **kwargs: u32(number, **kwargs)
u64: Callable[[bytes, Any], int] = lambda number, **kwargs: u64(number, **kwargs)


def dbg(script: str = '', pause_time: int = 3, **kwargs):
    if DEBUG:
        gdb.attach(sh, script, **kwargs)
        if pause_time == 0:
            pause()
        else:
            pause(pause_time)


# ------- Exploit -------