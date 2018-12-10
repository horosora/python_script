#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from pwn import *


context(os="linux", arch="i386")
#context.log_level = "debug"

if len(sys.argv) == 2 and sys.argv[1] == "r":
    conn = remote("0.1.2.3", 1000)
else:
    conn = process("./hoge")

#conn.recvuntil("hoge")
#payload = "hoge"
#conn.sendline(payload)
#conn.interactive()