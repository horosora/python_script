#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from scapy.all import *


args = sys.argv
if len(args) != 2:
    print("Usage: python " + args[0] + " [pcap file]")
    sys.exit()

key_codes1 = {
    0x04: ["a", "A"],
    0x05: ["b", "B"],
    0x06: ["c", "C"],
    0x07: ["d", "D"],
    0x08: ["e", "E"],
    0x09: ["f", "F"],
    0x0a: ["g", "G"],
    0x0b: ["h", "H"],
    0x0c: ["i", "I"],
    0x0d: ["j", "J"],
    0x0e: ["k", "K"],
    0x0f: ["l", "L"],
    0x10: ["m", "M"],
    0x11: ["n", "N"],
    0x12: ["o", "O"],
    0x13: ["p", "P"],
    0x14: ["q", "Q"],
    0x15: ["r", "R"],
    0x16: ["s", "S"],
    0x17: ["t", "T"],
    0x18: ["u", "U"],
    0x19: ["v", "V"],
    0x1a: ["w", "W"],
    0x1b: ["x", "X"],
    0x1c: ["y", "Y"],
    0x1d: ["z", "Z"],
    0x1e: ["1", "!"],
    0x1f: ["2", "@"],
    0x20: ["3", "#"],
    0x21: ["4", "$"],
    0x22: ["5", "%"],
    0x23: ["6", "^"],
    0x24: ["7", "&"],
    0x25: ["8", "*"],
    0x26: ["9", "("],
    0x27: ["0", ")"],
    0x28: ["[Enter]", "[Enter]"],
    0x29: ["[Escape]", "[Escape]"],
    0x2a: ["[Back Space]", "[Back Space]"],
    0x2b: ["[Tab]", "[Tab]"],
    0x2c: [" ", " "],
    0x2d: ["-", "_"],
    0x2e: ["=", "+"],
    0x2f: ["[", "{"],
    0x30: ["]", "}"],
    0x31: ["\\", "|"],
    0x33: [";", ":"],
    0x34: ["'", "\""],
    0x35: ["`", "~"],
    0x36: [",", "<"],
    0x37: [".", ">"],
    0x38: ["/", "?"],
    0x39: ["[Caps Lock]", "[Caps Lock]"],
    0x3a: ["[F1]", "[F1]"],
    0x3b: ["[F2]", "[F2]"],
    0x3c: ["[F3]", "[F3]"],
    0x3d: ["[F4]", "[F4]"],
    0x3e: ["[F5]", "[F5]"],
    0x3f: ["[F6]", "[F6]"],
    0x40: ["[F7]", "[F7]"],
    0x41: ["[F8]", "[F8]"],
    0x42: ["[F9]", "[F9]"],
    0x43: ["[F10]", "[F10]"],
    0x44: ["[F11]", "[F11]"],
    0x45: ["[F12]", "[F12]"],
    0x4f: ["[→]", "[→]"],
    0x50: ["[←]", "[←]"],
    0x51: ["[↓]", "[↓]"],
    0x52: ["[↑]", "[↑]"],
}

key_codes2 = {
    1: "Left-Ctrl",
    2: "Left-Shift",
    3: "Left-Alt",
    4: "Left-GUI",
    5: "Right-Ctrl",
    6: "Right-Shift",
    7: "Right-Alt",
    8: "Right-GUI"
}

key_input = ""
pcap = rdpcap(args[1])
for pkt in pcap:
    buf = pkt["Raw"].load
    # URB transfer type: URB_INTERRUPT (0x01)
    if len(buf) == 35 and buf[22] == "\x01":
        if ord(buf[29]) in key_codes1:
            if buf[27] == "\x00":
                key_input += key_codes1[ord(buf[29])][0]
            elif buf[27] == "\x02":
                key_input += key_codes1[ord(buf[29])][1]
            else:
                s = []
                i = 8
                for j in bin(ord(buf[27]))[2:]:
                    if int(j) == 1:
                        s.append(key_codes2[i])
                    i -= 1
                s.append(key_codes1[ord(buf[29])][0])
                key_input += "[" + " + ".join(s) + "]"

print(key_input)
