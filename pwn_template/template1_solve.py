#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import telnetlib
import struct
import time


def connect(host, port):
    return socket.create_connection((host, port))

def interactive(s):
    print("\n---------- interactive mode ----------\n")
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def p32(x):
    return struct.pack("<I", x)

def u32(x):
    return struct.unpack("<I", x)[0]

def p64(x):
    return struct.pack("<Q", x)

def u64(x):
    return struct.unpack("<Q", x)[0]


conn = connect("0.1.2.3", 1000)

#conn.recv(1024)

payload = ""

#conn.send(payload + "\n")
#time.sleep(1)

#interactive(conn)