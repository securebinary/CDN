---
title: "Vulnserver Setup - Prologue"
classes: wide
tag: 
  - "windows exploitation"
  - "vulnserver"
header:
  teaser: /assets/images/win-exp/windows-exp.png
ribbon: blue
description: "A simple guide to set up Vulnserver and insight about user land memory"
categories: ['Exploit-Development','Windows-Exploitation','Vulnserver']
---

In this series of blog post, we are going to see about the exploitation techniques in modern Windows systems. These things are very helpful for Offensive Security training and Red Teaming purposes. I aimed to cover the whole exploitation techniques that can be performed in this series which are available using our vulnerable application

- [Windows 10 Exploit Development - Prologue](#windows-10-exploit-development---prologue)
  - [Requirements](#requirements)
  - [Stack Memory](#stack-memory)
  - [Registers](#registers)
    - [Stack Pointer](#stack-pointer)
    - [Base Pointer](#base-pointer)
    - [Instruction Pointer](#instruction-pointer)
  - [Running Vulnserver](#running-vulnserver)
  - [Attaching Vulnserver to Immunity Debugger](#attaching-vulnserver-to-immunity-debugger)

## Requirements

- VMware Workstation Player
  - Used to run target machine and attacker machine
  - Always test exploits and execute vulnerable applications in a sandboxed environment, so that it doesn't affect the host OS
  - Download [VMware Workstation Player](https://www.vmware.com/in/products/workstation-player/workstation-player-evaluation.html)
- Windows 10 
  - Target machine used as host to run vulnerable application
  - Widely used modern Windows OS
  - Download [Windows 10 ISO](https://www.microsoft.com/en-in/evalcenter/evaluate-windows-10-enterprise)
- Kali Linux
  - An attacker machine which contains inbuilt tools for spiking
  - Suitable for attackers to craft payloads
  - Download [Kali Linux](https://www.kali.org/get-kali/)
- Vulnserver
  - A vulnerable application which has many flaws in it, so that an attacker can fuzz and exploit it
  - To be runned on target machine to craft a perfect exploit
  - Download [Vulnserver](https://thegreycorner.com/vulnserver.html)
- Immunity Debugger
  - Used to analyze the assembly instructions and application flow in the memory 
  - You may also use your choice of debugger too
  - Download [Immunity Debugger](https://www.immunityinc.com/products/debugger/)
- Python 
  - Used to perform arithmetic calculations while crafting payloads
  - Used to create fuzzing and exploit scripts for the vulnerable applications
  - Used to perform spiking using  ```boofuzz``` module
  - To install Python in Kali Linux
    - ```sudo apt install python3 -y```
- Metasploit 
  - Used to create patterns and find offset for that pattern while fuzzing
  - Used to create asm instructions by NASM shell
  - To install Metasploit Framework in Kali Linux
    - ```sudo apt install metasploit-framework -y```

## Stack Memory

Stack is a part of memory which used ```Linear``` data structure which follows ```LIFO (Last In First Out) / FILO (First In Last Out)``` order

A stack is a memory segment of computer's memory which stores temporary variables created by a function. In stack, variables are declared, stored and initialized during runtime

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/memory-block.png" style="width:40%">
</div>

It is a temporary storage memory. When the computing task is complete, the memory of the variable will be automatically erased. The stack section mostly contains methods, local variable, and reference variables

Remember that stack is always ```VOLATILE```


## Registers

Registers are memory storage which is fabricated inside processors designed for specific purposes

Registers can also be viewed as ```hardcoded variables``` in the memory

For more detail about [CPU registers](https://wiki.osdev.org/CPU_Registers_x86-64)

The three main registers which will be widely used are,

-   Stack Pointer (SP)
-   Base Pointer (BP)
-   Instrcution Pointer (IP)

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/stack-memory.png" style="width:40%">
</div>

### Stack Pointer

Stack Pointer is a register which always indicates the top element in the stack that will change any time a word or address is pushed or popped onto/off off the stacK

### Base Pointer

Base Pointer is a more convenient way for the compiler to keep track of a function's parameters and local variables than using the Stack Pointer directly.

### Instruction Pointer

This is an important register when it comes to exploit development

The Instruction Pointer (IP) is a register that holds the memory address of the next instruction to execute

The IP points to instructions in the code segment sequentially until it reaches a Jump (JMP), CALL, or other instruction, causing the pointer to jump to a new location in memory

## Running Vulnserver

Vulnserver is a vulnerable threaded TCP server application, which is intended to be used as a learning tool to teach about the process of software exploitation, as well as a good victim program for testing new exploitation techniques and shellcode

While running Vulnserver, it runs by default on ```port 9999```

```c
C:\vulnserver-master\vulnserver-master>dir
Volume in drive C has no label.
Volume Serial Number is C463-9DA9
Directory of C:\vulnserver-master\vulnserver-master
01/15/2022  05:45 AM    <DIR>          .
01/15/2022  05:45 AM    <DIR>          ..
01/15/2022  05:28 AM               519 COMPILING.TXT
01/15/2022  05:28 AM             3,254 essfunc.c
01/15/2022  05:28 AM            16,601 essfunc.dll
01/15/2022  05:28 AM             1,501 LICENSE.TXT
01/15/2022  05:28 AM             3,648 readme.md
01/15/2022  05:28 AM            10,935 vulnserver.c
01/15/2022  05:28 AM 29,624 vulnserver.exe
7 File(s)         66,082 bytes
2 Dir(s)  46,723,977,216 bytes free

C:\vulnserver-master\vulnserver-master>.\vulnserver.exe
Starting vulnserver version 1.00
Called essential function dll version 1.00
This is vulnerable software!
Do not allow access from untrusted systems or networks!
Waiting for client connections...                                                                                                                            
```

To make this application run on specific port,

```c
C:\vulnserver-master\vulnserver-master>.\vulnserver.exe 1234
Starting vulnserver version 1.00
Called essential function dll version 1.00
This is vulnerable software!
Do not allow access from untrusted systems or networks!
Waiting for client connections...
```

Disable ```Real Time Protection``` while running this exe application to prevent it being getting blocked

Connecting to Vulnserver from Attacker Machine using ```netcat```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ nc 192.168.116.141 1234
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

As you can see here, this Vulnserver provides many options to the user

The first step of an attacker is to ```spike``` and ```fuzz``` the vulnerable part of the program

## Attaching Vulnserver to Immunity Debugger

To analyse and debug the assembly instructions, registers and memory of the vulnserver, we need to attach the process of Vulnserver with the Immunity debugger

The debugger should be run in the same/higher privilege to attach the Vulnserver process

To attach a process in Immunity Debugger,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/attach.png">
</div>

And select the Vulnserver process to attach it,

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/attach-process.png">
</div>

Now we have successfully attached our process, we could view the application in a debugged view

<div align="center">
<img src="https://raw.githubusercontent.com/AidenPearce369/Vulnserver-Walkthrough/main/res/idbg-attached.png">
</div>

As for now, we have set up our environment

Lets start fuzzing and exploiting our vulnerable application to gain access on the target machine
