# LLMNR & NBT-NS Poisoning via Responder

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/24.png" style="width:80%">
</center>
<br>

- [LLMNR & NBT-NS Poisoning via Responder](#llmnr--nbt-ns-poisoning-via-responder)
  - [Prologue](#prologue)
  - [Attack Vector](#attack-vector)
  - [Analysing with Responder](#analysing-with-responder)
  - [Poisoning mNR Requests](#poisoning-mnr-requests)
  - [Cracking NTLMv2 Hash](#cracking-ntlmv2-hash)

## Prologue

Before we get into this blog, I wanna make sure that you understand what is ```LLMNR``` and ```NBT-NS``` and ```mDNS``` protocols are. These two protocols are widely used in ```Windows Environment``` which are ```enabled by default```. This poses a serious threat to the infrastructure, if it is being abused by attackers in the infrastructure network. The main goal of ```LLMNR``` and ```NBT-NS``` is to``` resolve the DNS hostnames``` from the client, when all other resolving methods are failed

LLMNR - Link Local Multicast Name Resolution

NBT-NS - NetBIOS Name Service

mDNS - Multicast DNS

Here ```LLMNR``` is the newer replacement for ```NBT-NS``` protocol, where NBT-NS protocol is still used along with LLMNR protocol to support the legacy machines. Whereas ```mDNS``` is the ```Linux``` alternative for LLMNR

So whenever a ```multicast call``` is made for hostname resolution, these three are used together to improve the compatibility and efficiency for resolving the hostnames

Windows machines does hostname resolution in the following steps if the preceeding one fails,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/22.png" style="width:80%">
</center>

1. The hostname is received from the client 
2. The hostname will be checked in hosts file of the local machine, ``` C:\Windows\System32\Drivers\etc\hosts```
3. The hostname will be checked on ```Local DNS Cache```
4. The hostname will be checked on ```DNS Server``` of the domain
5. The hostname will be checked from other machines by sending a ```multicast``` query using ```LLMNR``` and ```NBT-NS``` and ```mDNS``` protocols
  

Lets see an example how these protocols work,

Assuming a user/victim in an infrastructure of Windows AD Network tries to load a ```SMB Share``` with hostname, which may be real/malicious/fake

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/3.png" style="width:80%">
</center>

If either us or the Windows machine doesn't know what's the IP address of the hostname,it will try to lookup the IP address by resolving the hostname on the following order which we discussed above

If it was found in ```Hosts file```,```Local DNS Cache``` it would not have to interact outside the local machine, most frequently resolved hostname will be found here itself

When its not found, It will try to query the ```DNS Server``` to resolve the hostname

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/1.png" style="width:80%">
</center>

The client machine will send a request to the ```DNS Server``` to resolve the hostname

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/5.png" style="width:80%">
</center>

Since we have entered a unknown hostname to the DNS server it fails and return this response

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/6.png" style="width:80%">
</center>

Now our DNS server gave up, so its time we take our last option to resolve the hostname by sending ```mutlicast query``` through ```LLMNR``` , ```NBT-NS``` and ```mDNS``` protocols

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/2.png" style="width:80%">
</center>

This where the whole point of attack starts

## Attack Vector

In order to poison mNR ```( Multicast Name Resolution )``` (collective term for LLMNR, NBT-NS and mDNS), an attacker should be connected into a network where the victim is able to interact and send requests to the attacker

When a user/victim ```mistypes a hostname``` in his Windows machine (or) If the ```DNS server is poorly configured``` so that it is unable to resolve the hostname and passes it to mNR, which is the common scenario for this poisoning attack

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/23.png" style="width:80%">
</center>

We all have to do is, sit in patience so that they interact with our poisoned requests due to their misconfigurations

After the user/victim interacts with our poisoned requests, we will be acting as the legitimate hostname which they are trying to communicate and we will ask them for authentication, which makes them to send their ```NTLMv2 hash``` for authentication

That NTLMv2 hash is a valuable information in these kind of attacks which can be used for ```Initial accesss/Lateral Movement``` inside the organisation

[Responder](https://github.com/SpiderLabs/Responder) is a great tool used by Red Teamers and APT threat actors to gain initial access into an organisation environment

This tool allows us to poison LLMNR, NBT-NS, mDNS and baits the user/victim for authentication so we get their ```NTLMv2``` hashes, which can be further used for ```cracking hashes into plain text passwords``` (or) ```relaying attacks```

## Analysing with Responder

Lets analyze the Windows network for incoming mNR requests using ```Responder```

Running Responder in ```Analyze Mode```,

```c
responder -I eth1 -A
```

We can see that the poisoners are off and Responder also supports many servers for relaying related attacks (which will be discussed in later blog posts)

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/7.png" style="width:50%">
</center>

Now lets try to load an invalid hostname to trigger mNR requests

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/8.png" style="width:80%">
</center>

It will be generating mNR requests which we will be able to intercept using Responder, since we are connected in the same network

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/9.png" style="width:80%">
</center>

So we are able to see the mNR requests in Responder along with IP address of the client, the next step is to poision the mNR requests from our end to bait the client/victim for authentication

## Poisoning mNR Requests

Now lets run our ```Responder``` to poison the mNR requests to retrieve ```NTLMv2 hashes```

```c
responder -I eth1
```

Here we can see that the poisoners are active and mNR requests are being poisioned

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/12.png" style="width:50%">
</center>

Assuming the victim enters an invalid hostname/DNS server is poorly configured,

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/10.png" style="width:80%">
</center>

This will send ```mNR requests``` to resolve the hostname which will be poisioned by our ```Responder``` 

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/14.png" style="width:80%">
</center>

We can see that our poisoned requests is sent to the victim so that we act as the legitimate hostname

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/15.png" style="width:80%">
</center>

<br>

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/16.png" style="width:80%">
</center>

Now the ```NTLMv2 hash``` exchange will be taken place in the network from the victim to attacker

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/17.png" style="width:80%">
</center>

After exchange, our ```Responder``` would have grabbed the ```NTLMv2 hash``` by baiting the victim using poisoned mNR requests 

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/13.png" style="width:80%">
</center>

Now we had successfully retrieved the ```NTLMv2``` hash of the victim, eventhough after grabbing NTLMv2 hash the Windows machine requests for authentication which is not needed for us in this scenario

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/11.png" style="width:80%">
</center>

## Cracking NTLMv2 Hash

Now we can use the ```NTLMv2 hash``` for lateral movement using ```Relaying attacks``` or we can simply crack that using our wordlist to gain the plain text password which is more useful and persistent

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/18.png" style="width:80%">
</center>

Lets use ```hashcat``` to crack the ```NTLMv2 hash``` with ```rockyou.txt```

```c
hashcat -m 5600 user.hash rockyou.txt
```

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/19.png" style="width:80%">
</center>

<br>

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/20.png" style="width:80%">
</center>

We have cracked our hash into plain text password, with this we can perform lateral movement also

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/my-CDN/main/LLMNR-NBT-NS-Poisoning/21.png" style="width:80%">
</center>

Now we have shell as the victim user on his machine
